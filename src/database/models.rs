use diesel::prelude::*;

#[derive(Queryable, Selectable, Insertable, Debug)]
#[diesel(table_name = super::schema::users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct User {
    pub username: String,
    pub devices: String,
}

#[derive(Queryable, Selectable, Debug, Insertable)]
#[diesel(table_name = super::schema::queued_messages)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct QueuedMessage {
    pub id: i64,
    pub recipient: String,
    pub sender: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Queryable, Selectable, Insertable, Debug)]
#[diesel(table_name = super::schema::ids)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct IdsUser {
    pub username: String,
    pub user_certificate: Vec<u8>,
}

#[derive(Queryable, Selectable, Insertable, Debug, AsChangeset)]
#[diesel(table_name = super::schema::devices)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Device {
    pub device_id: String,
    pub device_certificate: Vec<u8>,
    pub account: Option<String>,
}