pub mod communication {
    tonic::include_proto!("communication");
}

mod database;
mod util;

use std::{collections::HashMap, io::ErrorKind, pin::Pin, sync::Arc};

use crate::{communication::client_broker_server::*, util::match_for_io_error};
use database::{models::{Device, IdsUser, User, QueuedMessage}, Database};
use communication::{AccountLinkAckPacket, AccountLinkStatus, AccountRegistration, AccountRegistrationResponse, AuthenticationAckPacket, ClientPacket, ClientPacketType, DeviceAuthenticationPacket, DeviceRegistrationRequest, DeviceRegistrationResponse, Empty, GreetingRequest, GreetingResponse, IncomingMessagePacket, LinkAccountPacket, OutgoingMessageAckPacket, OutgoingMessageAckStatus, RootKey, ServerPacket, ServerPacketType, UserIdentity, UserIdentityRequest};
use openssl::{asn1::Asn1Time, error::ErrorStack, hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, rsa::Rsa, sign::Verifier, x509::{X509Req, X509}};
use tonic::{transport::Server, Request, Response, Status, Streaming};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tokio::{fs, sync::{mpsc, Mutex}};
use util::now;
use uuid::Uuid;
use log::{debug, info, warn};

pub struct BrokerServer {
    db: Arc<Mutex<Database>>,
    root_keypair: PKey<Private>,
    active_sockets: Arc<Mutex<HashMap<String, mpsc::Sender<ServerPacket>>>>,
}

#[tonic::async_trait]
impl ClientBroker for BrokerServer {
    type ReceiveMessagesStream = Pin<Box<dyn Stream<Item = Result<ServerPacket, Status>> + Send>>;

    async fn receive_messages(
        &self,
        request: Request<Streaming<ClientPacket>>,
    ) -> Result<Response<Self::ReceiveMessagesStream>, Status> {
        let mut in_stream = request.into_inner();
        let (tx, rx) = mpsc::channel(128);
        let _ = tx.send(Ok(ServerPacket { 
            ..Default::default()
        })).await;
        
        let active_sockets = self.active_sockets.clone();
        let db = self.db.clone();
        let root_keypair = self.root_keypair.clone();

        // this spawn here is required if you want to handle connection error.
        // If we just map `in_stream` and write it back as `out_stream` the `out_stream`
        // will be dropped when connection error occurs and error will never be propagated
        // to mapped version of `in_stream`.
        tokio::spawn(async move {
            let mut setup = false;
            let mut device_id = None;
            while let Some(result) = in_stream.next().await {
                let mut db_lock = db.lock().await;
                match result {
                    Ok(v) => {
                        if !setup {
                            if v.packet_type() == ClientPacketType::Authentication {
                                if let Some(authentication) = v.authentication {
                                    if let Ok(device) = db_lock.get_device(&authentication.device_id) {
                                        if let Ok(_) = verify_device_authentication(&device, &authentication, &root_keypair) {
                                            let (message_sender, mut message_receiver) = mpsc::channel(128);
                                            active_sockets.lock().await.insert(authentication.device_id.clone(), message_sender);
                                            let tx_copy = tx.clone();
                                            tokio::spawn(async move {
                                                while let Some(message) = message_receiver.recv().await {
                                                    if let Err(_) = tx_copy.send(Ok(message)).await {
                                                        break;
                                                    }
                                                }
                                            });
                                            device_id = Some(authentication.device_id);
                                            setup = true;
                                            let _ = tx.send(Ok(ServerPacket { 
                                                packet_type: ServerPacketType::AuthenticationAck.into(), 
                                                authentication_ack: Some(AuthenticationAckPacket {
                                                    status: communication::Status::Ok.into(),
                                                    id: v.id,
                                                }),
                                                ..Default::default()
                                            })).await;
                                            if let Ok(queued_messages) = db_lock.load_queued_messages(device_id.as_ref().unwrap(), true) {
                                                for message in queued_messages {
                                                    let _ = tx.send(Ok(ServerPacket { 
                                                        packet_type: ServerPacketType::IncomingMessage.into(), 
                                                        incoming_message: Some(IncomingMessagePacket {
                                                            from: message.sender,
                                                            message: message.data,
                                                        }),
                                                        ..Default::default()
                                                    })).await;
                                                }
                                            }
                                            debug!("{} ({}) connected.", device.account.as_ref().unwrap_or(&"<no account>".into()), device_id.as_ref().unwrap());
                                            continue;
                                        } else {
                                            warn!("auth failed: verify failed");
                                        }
                                    } else {
                                        warn!("auth failed: invalid device");
                                    }
                                } else {
                                    warn!("auth failed: no packet");
                                }
                            }
                            let _ = tx.send(Err(Status::unauthenticated("Send an DeviceAuthenticationPacket as the first message"))).await;
                            break;
                        }
                        let Some(device_id) = device_id.as_ref() else { continue; };
                        let Ok(device) = db_lock.get_device(&device_id) else { continue; };
                        let response = match v.packet_type() {
                            ClientPacketType::OutgoingMessage => {
                                if let Some(message) = v.outgoing_message {
                                    let mut status: OutgoingMessageAckStatus = OutgoingMessageAckStatus::SendSuccess;
                                    if let Ok(account) = db_lock.get_user(&message.recipient) {
                                        'a: for recipient_device_id in account.devices.split(";") {
                                            if recipient_device_id.trim().is_empty() {
                                                continue 'a;
                                            }
                                            let sender_account = device.account.clone();
                                            if let Some(recipient_sender) = active_sockets.lock().await.get(recipient_device_id) {
                                                if let Err(e) = recipient_sender.send(ServerPacket {
                                                    packet_type: ServerPacketType::IncomingMessage.into(), 
                                                    incoming_message: Some(IncomingMessagePacket {
                                                        from: sender_account,
                                                        message: message.message.clone(),
                                                    }),
                                                    ..Default::default()
                                                }).await {
                                                    warn!("failed to send {e}");
                                                    status = OutgoingMessageAckStatus::FailedToDeliver;
                                                }
                                            } else {
                                                if let Err(e) = db_lock.queue_message(QueuedMessage {
                                                    data: message.message.clone(),
                                                    recipient: recipient_device_id.to_string(),
                                                    id: v.id,
                                                    sender: sender_account,

                                                }) {
                                                    warn!("failed to queue {e}");
                                                    status = OutgoingMessageAckStatus::FailedToDeliver;
                                                }
                                            }
                                        }
                                    } else {
                                        status = OutgoingMessageAckStatus::InvalidSendRequest;
                                    }
                                    ServerPacket { 
                                        packet_type: ServerPacketType::OutgoingMessageAck.into(), 
                                        outgoing_message_ack: Some(OutgoingMessageAckPacket {
                                            status: status.into(),
                                            id: v.id,
                                        }),
                                        ..Default::default()
                                    }
                                } else {
                                    ServerPacket { 
                                        packet_type: ServerPacketType::OutgoingMessageAck.into(), 
                                        outgoing_message_ack: Some(OutgoingMessageAckPacket {
                                            status: OutgoingMessageAckStatus::InvalidSendRequest.into(),
                                            id: v.id,
                                        }),
                                        ..Default::default()
                                    }
                                }
                            },
                            ClientPacketType::UnlinkAccount => {
                                let res = db.lock().await.unlink_device(&device_id);
                                ServerPacket { 
                                    packet_type: ServerPacketType::AccountLinkAck.into(), 
                                    account_link_ack: Some(AccountLinkAckPacket {
                                        status: if res.is_ok() { AccountLinkStatus::LinkSuccess } else { AccountLinkStatus::InternalError }.into(),
                                        id: v.id,
                                    }),
                                    ..Default::default()
                                }
                            },
                            ClientPacketType::LinkAccount => {
                                let invalid_req = ServerPacket { 
                                    packet_type: ServerPacketType::AccountLinkAck.into(), 
                                    account_link_ack: Some(AccountLinkAckPacket {
                                        status: AccountLinkStatus::InvalidLinkRequest.into(),
                                        id: v.id,
                                    }),
                                    ..Default::default()
                                };
                                if let Some(link_req) = v.link_account {
                                    if let Ok(account) = db_lock.get_ids_user(&link_req.username) {
                                        if let Ok(_) = verify_link_request(&account, &link_req, &device_id, &root_keypair) {
                                            if device.account.is_none() {
                                                if let Ok(_) = db_lock.link_device(&account.username, &device_id) {
                                                    ServerPacket { 
                                                        packet_type: ServerPacketType::AccountLinkAck.into(), 
                                                        account_link_ack: Some(AccountLinkAckPacket {
                                                            status: AccountLinkStatus::LinkSuccess.into(),
                                                            id: v.id,
                                                        }),
                                                        ..Default::default()
                                                    }
                                                } else {
                                                    ServerPacket { 
                                                        packet_type: ServerPacketType::AccountLinkAck.into(), 
                                                        account_link_ack: Some(AccountLinkAckPacket {
                                                            status: AccountLinkStatus::InternalError.into(),
                                                            id: v.id,
                                                        }),
                                                        ..Default::default()
                                                    }
                                                }
                                            } else {
                                                ServerPacket { 
                                                    packet_type: ServerPacketType::AccountLinkAck.into(), 
                                                    account_link_ack: Some(AccountLinkAckPacket {
                                                        status: AccountLinkStatus::LogOutFirst.into(),
                                                        id: v.id,
                                                    }),
                                                    ..Default::default()
                                                }
                                            }
                                        } else {
                                            ServerPacket { 
                                                packet_type: ServerPacketType::AccountLinkAck.into(), 
                                                account_link_ack: Some(AccountLinkAckPacket {
                                                    status: AccountLinkStatus::FailedToVerify.into(),
                                                    id: v.id,
                                                }),
                                                ..Default::default()
                                            }
                                        }
                                    } else {
                                        invalid_req
                                    }
                                } else {
                                    invalid_req
                                }
                            }
                            ClientPacketType::Authentication => { panic!("code should continue; before this")},
                        };
                        if let Err(_) = tx.send(Ok(response)).await {
                            warn!("breaking loop, messageack failed to send");
                            break;
                        }
                    },
                    Err(err) => {
                        if let Some(io_err) = match_for_io_error(&err) {
                            if io_err.kind() == ErrorKind::BrokenPipe {
                                // here you can handle special case when client
                                // disconnected in unexpected way
                                debug!("\tclient disconnected: broken pipe");
                                break;
                            }
                        }

                        match tx.send(Err(err)).await {
                            Ok(_) => (),
                            Err(_err) => break, // response was dropped
                        }
                    }
                }
            }
            if let Some(device_id) = &device_id {
                active_sockets.lock().await.remove(device_id);
            }
            debug!("\tstream ended");
        });

        // echo just write the same data that was received
        let out_stream = ReceiverStream::new(rx);

        Ok(Response::new(
            Box::pin(out_stream) as Self::ReceiveMessagesStream
        ))
    }

    async fn greeting(
        &self,
        request: Request<GreetingRequest>,
    ) -> Result<Response<GreetingResponse>, Status> {
        Ok(Response::new(GreetingResponse { greeting: format!("Hello {}!", request.into_inner().name) }))
    }

    async fn register_account(
        &self,
        request: Request<AccountRegistration>,
    ) -> Result<Response<AccountRegistrationResponse>, Status> {
        let account = request.into_inner();
        if self.db.lock().await.account_exists(&account.username) {
            return Ok(Response::new(AccountRegistrationResponse { status: communication::Status::AccountExists.into(), certificate: None }));
        }
        let csr = X509Req::from_der(&account.csr).map_err(|_| Status::invalid_argument("csr is invalid, der format X509Req"))?;
        let mut certificate = X509::builder().map_err(|_| Status::internal("mb gang"))?;
        certificate.set_pubkey(csr.public_key().map_err(|_| Status::invalid_argument("csr is invalid, set public key"))?.as_ref()).map_err(|_| Status::internal("mb gang"))?;
        let mut x509_name = openssl::x509::X509NameBuilder::new().map_err(|_| Status::internal("mb gang"))?;
        x509_name.append_entry_by_text("C", "US").map_err(|_| Status::internal("mb gang"))?;
        x509_name.append_entry_by_text("ST", "WA").map_err(|_| Status::internal("mb gang"))?;
        x509_name.append_entry_by_text("O", "Christopher Huntwork").map_err(|_| Status::internal("mb gang"))?;
        x509_name.append_entry_by_nid(Nid::ACCOUNT, &account.username).map_err(|_| Status::internal("mb gang"))?;
        certificate.set_not_before(Asn1Time::from_unix(now() as i64).unwrap().as_ref()).map_err(|_| Status::internal("mb gang"))?;
        certificate.set_not_after(Asn1Time::days_from_now(365*10).unwrap().as_ref()).map_err(|_| Status::internal("mb gang"))?;
        certificate.set_subject_name(&x509_name.build()).map_err(|_| Status::internal("mb gang"))?;
        certificate.sign(&self.root_keypair, MessageDigest::sha1()).map_err(|_| Status::internal("mb gang"))?;
        let certificate_der = certificate.build().to_der().map_err(|_| Status::internal("mb gang"))?;
        self.db.lock().await.put_ids_user(IdsUser {
            username: account.username.clone(),
            user_certificate: certificate_der.clone()
        }).map_err(|_| Status::internal("mb gang"))?;
        self.db.lock().await.put_user(User {
            username: account.username,
            devices: "".into(),
        }).map_err(|_| Status::internal("mb gang"))?;
        return Ok(Response::new(AccountRegistrationResponse { status: communication::Status::Ok.into(), certificate: Some(certificate_der) }));
    }
    
    async fn get_root_key(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<RootKey>, Status> {
        return Ok(Response::new(RootKey {
            public_key: self.root_keypair.public_key_to_der().map_err(|_| Status::internal("mb gang"))?
        }));
    }
    
    async fn register_device(
        &self,
        request: Request<DeviceRegistrationRequest>,
    ) -> Result<Response<DeviceRegistrationResponse>, Status> {
        let device_id = Uuid::new_v4().to_string();
        let csr = X509Req::from_der(&request.into_inner().csr).map_err(|_| Status::invalid_argument("csr is invalid, der format X509Req"))?;
        let mut certificate = X509::builder().map_err(|_| Status::internal("mb gang"))?;
        certificate.set_pubkey(csr.public_key().map_err(|_| Status::invalid_argument("csr is invalid, set public key"))?.as_ref()).map_err(|_| Status::internal("mb gang"))?;
        let mut x509_name = openssl::x509::X509NameBuilder::new().map_err(|_| Status::internal("mb gang"))?;
        x509_name.append_entry_by_text("C", "US").map_err(|_| Status::internal("mb gang"))?;
        x509_name.append_entry_by_text("ST", "WA").map_err(|_| Status::internal("mb gang"))?;
        x509_name.append_entry_by_text("O", "Christopher Huntwork").map_err(|_| Status::internal("mb gang"))?;
        x509_name.append_entry_by_nid(Nid::COMMONNAME, &device_id).map_err(|_| Status::internal("mb gang"))?;
        certificate.set_subject_name(&x509_name.build()).map_err(|_| Status::internal("mb gang"))?;
        certificate.set_not_before(Asn1Time::from_unix(now() as i64).unwrap().as_ref()).map_err(|_| Status::internal("mb gang"))?;
        certificate.set_not_after(Asn1Time::days_from_now(365*10).unwrap().as_ref()).map_err(|_| Status::internal("mb gang"))?;
        certificate.sign(&self.root_keypair, MessageDigest::sha1()).map_err(|_| Status::internal("mb gang"))?;
        let certificate_der = certificate.build().to_der().map_err(|_| Status::internal("mb gang"))?;
        self.db.lock().await.put_device(Device {
            device_id,
            device_certificate: certificate_der.clone(),
            account: None,
        }).map_err(|_| Status::internal("mb gang"))?;
        Ok(Response::new(DeviceRegistrationResponse {
            status: communication::Status::Ok.into(),
            certificate: certificate_der,
        }))
    }

    async fn get_user_identity(
        &self,
        request: Request<UserIdentityRequest>,
    ) -> Result<Response<UserIdentity>, Status> {
        let user = self.db.lock().await.get_ids_user(&request.into_inner().username).map_err(|_| Status::internal("mb gang"))?;
        Ok(Response::new(UserIdentity { username: user.username, certificate: user.user_certificate }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let db = Database::establish(":memory:")?;
    
    let root_keypair = load_keypair().await.unwrap_or_else(|_| { PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap() });

    let addr = "0.0.0.0:50051".parse().unwrap();
    let greeter = BrokerServer {
        db: Arc::new(Mutex::new(db)),
        root_keypair,
        active_sockets: Arc::new(Mutex::new(HashMap::new())),
    };

    info!("Server listening on {}", addr);

    Server::builder()
        .add_service(ClientBrokerServer::new(greeter))
        .serve(addr)
        .await?;

    Ok(())
}

async fn load_keypair() -> Result<PKey<Private>, Box<dyn std::error::Error>>{
    let keypair_der = fs::read("root_keypair.der").await?;
    Ok(PKey::from_rsa(Rsa::private_key_from_der(&keypair_der)?)?)
}

fn verify_device_authentication(device: &Device, authentication: &DeviceAuthenticationPacket, root_keypair: &PKey<Private>) -> Result<(), ErrorStack> {
    let certificate = X509::from_der(&device.device_certificate)?;
    if !certificate.verify(root_keypair)? {
        warn!("device verification failed: not signed by root");
        return Err(ErrorStack::get());
    }
    let public_key = certificate.public_key()?;
    let mut verifier = Verifier::new(MessageDigest::sha1(), public_key.as_ref())?;
    let mut payload = authentication.timestamp.to_be_bytes().to_vec();
    payload.append(&mut authentication.device_id.as_bytes().to_vec());
    verifier.update(&payload)?;
    if !verifier.verify(&authentication.signature)? {
        warn!("device verification failed: signature invalid");
        return Err(ErrorStack::get());
    }
    Ok(())
}

fn verify_link_request(user: &IdsUser, link_req: &LinkAccountPacket, device_id: &str, root_keypair: &PKey<Private>) -> Result<(), ErrorStack> {
    let certificate = X509::from_der(&user.user_certificate)?;
    if !certificate.verify(root_keypair)? {
        return Err(ErrorStack::get());
    }
    let public_key = certificate.public_key()?;
    let mut verifier = Verifier::new(MessageDigest::sha1(), public_key.as_ref())?;
    let mut payload = link_req.timestamp.to_be_bytes().to_vec();
    payload.append(&mut device_id.as_bytes().to_vec());
    verifier.update(&payload)?;
    if !verifier.verify(&link_req.signature)? {
        return Err(ErrorStack::get());
    }
    Ok(())
} 