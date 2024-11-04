CREATE TABLE users (
  username TEXT NOT NULL PRIMARY KEY,
  devices TEXT
);
CREATE TABLE queued_messages (
  id BIGINT NOT NULL PRIMARY KEY,
  recipient TEXT,
  sender TEXT,
  body DATA
);
CREATE TABLE ids (
  username TEXT NOT NULL PRIMARY KEY,
  user_certificate DATA
);
CREATE TABLE devices (
  device_id TEXT NOT NULL PRIMARY KEY,
  device_certificate DATA,
  account TEXT
)