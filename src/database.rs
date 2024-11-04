pub mod models;
pub mod schema;

use diesel::{Connection, SqliteConnection};
use models::{Device, IdsUser, QueuedMessage, User};
use diesel::prelude::*;
use self::schema::*;

pub struct Database {
    conn: SqliteConnection,
}

use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[allow(unused)]
impl Database {
    pub fn establish(database_uri: &str) -> Result<Self, diesel::ConnectionError> {
        let mut _self = Self {
            conn: SqliteConnection::establish(database_uri)?,
        };
        _self.conn.run_pending_migrations(MIGRATIONS).unwrap();
        Ok(_self)
    }

    pub fn get_users(&mut self) -> Result<Vec<User>, diesel::result::Error> {
        users::dsl::users.select(User::as_select()).load(&mut self.conn)
    }

    pub fn get_user(&mut self, username: &str) -> Result<User, diesel::result::Error> {
        users::dsl::users.filter(users::dsl::username.like(username)).select(User::as_select()).first(&mut self.conn)
    }

    pub fn link_device(&mut self, username: &str, device_id: &str) -> Result<(), diesel::result::Error> {
        let user = self.get_user(username)?;
        let device = self.get_device(device_id)?;
        if device.account.is_some() {
            return Err(diesel::result::Error::NotFound);
        }
        let mut devices: Vec<&str> = user.devices.split(";").collect();
        devices.push(device_id);
        let devices = devices.join(";");
        diesel::update(users::dsl::users.find(username))
            .set(users::dsl::devices.eq(devices))
            .execute(&mut self.conn)?;
        diesel::update(devices::dsl::devices.find(device_id))
            .set(devices::dsl::account.eq(username))
            .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn unlink_device(&mut self, device_id: &str) -> Result<(), diesel::result::Error> {
        let mut device = self.get_device(device_id)?;
        device.account = None;
        diesel::update(devices::dsl::devices.find(device_id))
            .set(device)
            .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn user_exists(&mut self, username: &str) -> bool {
        self.get_user(username).is_ok()
    }

    pub fn put_user(&mut self, user: User) -> Result<(), diesel::result::Error> {
        diesel::insert_into(users::dsl::users).values(&user).execute(&mut self.conn)?;
        Ok(())
    }

    pub fn queue_message(&mut self, message: QueuedMessage) -> Result<(), diesel::result::Error> {
        diesel::insert_into(queued_messages::dsl::queued_messages).values(&message).execute(&mut self.conn)?;
        Ok(())
    }

    pub fn load_queued_messages(&mut self, recipient: &str, remove: bool) -> Result<Vec<QueuedMessage>, diesel::result::Error> {
        let loaded = queued_messages::dsl::queued_messages.select(QueuedMessage::as_select()).filter(queued_messages::dsl::recipient.like(&recipient)).load(&mut self.conn)?;
        if remove {
            diesel::delete(queued_messages::dsl::queued_messages.filter(queued_messages::dsl::recipient.like(recipient))).execute(&mut self.conn)?;
        }
        Ok(loaded)
    }

    pub fn get_ids_user(&mut self, username: &str) -> Result<IdsUser, diesel::result::Error> {
        ids::dsl::ids.filter(ids::dsl::username.like(username)).select(IdsUser::as_select()).first(&mut self.conn)
    }

    pub fn put_ids_user(&mut self, ids_user: IdsUser) -> Result<(), diesel::result::Error> {
        diesel::insert_into(ids::dsl::ids).values(&ids_user).execute(&mut self.conn)?;
        Ok(())
    }

    pub fn account_exists(&mut self, username: &str) -> bool {
        self.get_ids_user(username).is_ok()
    }

    pub fn get_device(&mut self, device_id: &str) -> Result<Device, diesel::result::Error> {
        devices::dsl::devices.filter(devices::dsl::device_id.like(device_id)).select(Device::as_select()).first(&mut self.conn)
    }

    pub fn put_device(&mut self, device: Device) -> Result<(), diesel::result::Error> {
        diesel::insert_into(devices::dsl::devices).values(&device).execute(&mut self.conn)?;
        Ok(())
    }
}