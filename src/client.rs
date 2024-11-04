use communication::{client_broker_client::ClientBrokerClient, AccountRegistration, ClientPacket, ClientPacketType, DeviceAuthenticationPacket, DeviceRegistrationRequest, LinkAccountPacket, OutgoingMessagePacket, PeerMessage, ServerPacket, ServerPacketType, UserIdentityRequest};
use log::{info, warn};
use openssl::{encrypt::{Decrypter, Encrypter}, hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, rsa::Rsa, sign::{Signer, Verifier}, x509::{X509Req, X509}};
use prost::Message;
use thiserror::Error;
use tokio::{sync::{mpsc, Mutex}, time::sleep};
use std::{sync::Arc, time::Duration};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{transport::Channel, Streaming};
use util::now;

pub mod communication {
    tonic::include_proto!("communication");
}

mod util;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let username = "christopher";
    let mut client = Client::register(username).await?;
    let (tx, mut rx) = client.connect().await?;
    
    tokio::spawn(async move {
        loop {
            let peer_message = client.create_peer_message("christopher", "Hello World!".as_bytes()).await.unwrap();
            tx.send(("christopher".into(), peer_message.encode_to_vec())).await.unwrap();
            sleep(Duration::from_secs(1)).await;
        }
    });

    while let Some(message) = rx.recv().await {
        info!("received message: {}", String::from_utf8_lossy(&message));
    }

    Ok(())
}


async fn verify_decrypt_message(client: Arc<Mutex<ClientBrokerClient<Channel>>>, peer_message: PeerMessage, account_key: &PKey<Private>) -> Result<Vec<u8>, ClientError> {
    let ids_user = client.lock().await.get_user_identity(UserIdentityRequest { username: peer_message.sender_account.clone() }).await?.into_inner();
    let sender_cert = X509::from_der(&ids_user.certificate)?;
    let sender_key = sender_cert.public_key()?;
    let mut verifier = Verifier::new(MessageDigest::sha1(), sender_key.as_ref())?;
    verifier.update(&peer_message.encrypted_message)?;
    if !verifier.verify(&peer_message.message_signature)? {
        return Err(ClientError::VerificationFailed);
    }
    let decrypter = Decrypter::new(account_key)?;
    let mut decrypted_message = vec![0u8; decrypter.decrypt_len(&peer_message.encrypted_message)?];
    decrypter.decrypt(&peer_message.encrypted_message, &mut decrypted_message)?;
    Ok(decrypted_message)
}

struct Client {
    grpc_client: Arc<Mutex<ClientBrokerClient<Channel>>>,
    account_key: Option<PKey<Private>>,
    username: Option<String>,
    account_linked: bool,
    device_key: Option<PKey<Private>>,
    device_id: Option<String>,

}

#[derive(Debug, Error)]
enum ClientError {
    #[error("Client is not ready to connect")]
    NotReady,
    #[error("Grpc error {0}")]
    GrpcError(#[from] tonic::Status),
    #[error("Connection error {0}")]
    ConnectionError(#[from] tonic::transport::Error),
    #[error("Crypto error {0}")]
    CryptoError(#[from] openssl::error::ErrorStack),
    #[error("Message verification failed")]
    VerificationFailed,
    #[error("Server returned non-success response: {0:?}")]
    RegisterationNotSuccessful(communication::Status),
    #[error("Unexpected server response, {0}")]
    UnexpectedServerResponse(String)
}

impl Client {
    async fn create_client() -> Result<ClientBrokerClient<Channel>, ClientError> {
        Ok(ClientBrokerClient::connect("http://0.0.0.0:50051").await?)
    }

    async fn create_peer_message(&mut self, recipient: &str, inner_message: &[u8]) -> Result<PeerMessage, ClientError> {
        let Some(account_key) = &self.account_key else { return Err(ClientError::NotReady) };
        let Some(username) = &self.username else { return Err(ClientError::NotReady) };
        let ids_user = self.grpc_client.lock().await.get_user_identity(UserIdentityRequest { username: recipient.into() }).await?;
        let recipient_cert = X509::from_der(&ids_user.into_inner().certificate)?;
        let recipient_public_key = recipient_cert.public_key()?;
        let encrypter = Encrypter::new(recipient_public_key.as_ref())?;
        let mut encrypted_message = vec![0u8; encrypter.encrypt_len(inner_message)?];
        encrypter.encrypt(inner_message, &mut encrypted_message)?;
        let mut signer = Signer::new(MessageDigest::sha1(), account_key.as_ref())?;
        signer.update(&encrypted_message)?;
        let message_signature = signer.sign_to_vec()?;
        Ok(PeerMessage {
            sender_account: username.into(),
            id: rand::random(),
            encrypted_message,
            message_signature,
        })
    }

    pub async fn register(username: &str) -> Result<Self, ClientError> {
        let client = Self::create_client().await?;
        let mut _self = Self {
            grpc_client: Arc::new(Mutex::new(client)),
            username: Some(username.into()),
            account_key: None,
            account_linked: false,
            device_key: None,
            device_id: None,
        };
        let account_key = _self.register_account(username).await?;
        _self.account_key = Some(account_key);
        let (device_key, device_id) = _self.register_device().await?;
        _self.device_key = Some(device_key);
        _self.device_id = Some(device_id);
        Ok(_self)
    }

    async fn register_account(&mut self, username: &str) -> Result<PKey<Private>, ClientError> {
        let keypair = Rsa::generate(2048)?;
        let mut csr = X509Req::builder()?;
        let pkey = PKey::from_rsa(keypair)?;
        csr.set_pubkey(&pkey)?;
        csr.sign(&pkey, MessageDigest::sha1())?;
        let res = self.grpc_client.lock().await.register_account(AccountRegistration {
            username: username.into(),
            csr: csr.build().to_der()?,
        }).await?;
        let status = res.into_inner().status();
        if status != communication::Status::Ok {
            return Err(ClientError::RegisterationNotSuccessful(status));
        }
        Ok(pkey)
    }
    
    async fn register_device(&mut self) -> Result<(PKey<Private>, String), ClientError> {
        let keypair = Rsa::generate(2048)?;
        let mut csr = X509Req::builder()?;
        let pkey = PKey::from_rsa(keypair)?;
        csr.set_pubkey(&pkey)?;
        csr.sign(&pkey, MessageDigest::sha1())?;
        let res = self.grpc_client.lock().await.register_device(DeviceRegistrationRequest {
            csr: csr.build().to_der()?,
        }).await?.into_inner();
        if res.status != communication::Status::Ok.into() {
            return Err(ClientError::RegisterationNotSuccessful(res.status()));
        }
        let certificate = X509::from_der(&res.certificate)?;
        let Some(Some(device_id)) = certificate.subject_name().entries_by_nid(Nid::COMMONNAME).next().map(|commonname| 
            commonname.data().as_utf8().ok().map(|it| it.to_string())) else { return Err(ClientError::UnexpectedServerResponse("expected subject name to have commonname".into())) };
        Ok((pkey, device_id))
    }

    async fn receive_messages(&mut self) -> Result<(mpsc::Sender<ClientPacket>, Streaming<ServerPacket>), ClientError> {
        let (tx, rx) = mpsc::channel(128);
    
        let response = self.grpc_client.lock().await
            .receive_messages(ReceiverStream::new(rx))
            .await?;
    
        let resp_stream = response.into_inner();
        Ok((tx, resp_stream))
    }

    async fn connect(&mut self) -> Result<(mpsc::Sender<(String, Vec<u8>)>, mpsc::Receiver<Vec<u8>>), ClientError> {
        let (message_sender, mut message_receiver) = self.receive_messages().await.unwrap();

        let Some(device_key) = &self.device_key else { return Err(ClientError::NotReady) };
        let Some(device_id) = &self.device_id else { return Err(ClientError::NotReady) };
        let Some(account_key) = &self.account_key else { return Err(ClientError::NotReady) };
        let Some(username) = &self.username else { return Err(ClientError::NotReady) };
        
        let mut signer = Signer::new(MessageDigest::sha1(), device_key.as_ref())?;
        let timestamp = now() as i64;
        let mut payload = timestamp.to_be_bytes().to_vec();
        payload.append(&mut device_id.as_bytes().to_vec());
        signer.update(&payload)?;
        let device_signature = signer.sign_to_vec()?;

        message_sender.send(ClientPacket {
            packet_type: ClientPacketType::Authentication.into(),
            authentication: Some(DeviceAuthenticationPacket {
                device_id: device_id.clone(),
                timestamp,
                signature: device_signature,
            }),
            ..Default::default()
        }).await.unwrap();
        if !self.account_linked {
            let mut signer = Signer::new(MessageDigest::sha1(), account_key.as_ref())?;
            let mut payload = timestamp.to_be_bytes().to_vec();
            payload.append(&mut device_id.as_bytes().to_vec());
            signer.update(&payload)?;
            let account_signature = signer.sign_to_vec()?;
            let link_account_packet = LinkAccountPacket {
                timestamp,
                username: username.to_string(),
                signature: account_signature,
            };
            message_sender.send(ClientPacket {
                packet_type: ClientPacketType::LinkAccount.into(),
                link_account: Some(link_account_packet),
                ..Default::default()
            }).await.unwrap();
        }

        let (message_sender_tx, mut message_sender_rx) = mpsc::channel(128);
        tokio::spawn(async move {
            while let Some((recipient, message)) = message_sender_rx.recv().await {
                message_sender.send(ClientPacket {
                    packet_type: ClientPacketType::OutgoingMessage.into(),
                    outgoing_message: Some(OutgoingMessagePacket {
                        recipient,
                        message,
                    }),
                    ..Default::default()
                }).await.unwrap();
            }
        });

        let (decrypted_message_tx, decrypted_message_rx) = mpsc::channel(128);
        let grpc_client_arc = self.grpc_client.clone();
        let account_key_copy = account_key.clone();
        tokio::spawn(async move {
            while let Some(received) = message_receiver.next().await {
                let received = received.unwrap();
                if received.packet_type() == ServerPacketType::IncomingMessage {
                    if let Some(incoming_message) = received.incoming_message {
                        if let Ok(peer_message) = PeerMessage::decode(&*incoming_message.message) {
                            match verify_decrypt_message(grpc_client_arc.clone(), peer_message, &account_key_copy).await {
                                Ok(message) => decrypted_message_tx.send(message).await.unwrap(),
                                Err(e) => warn!("failed to verify message: {e}"),
                            }
                        }
                    }
                }
            }
        });
        Ok((message_sender_tx, decrypted_message_rx))
    }
}