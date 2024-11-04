diesel::table! {
    users (username) {
        username -> Text,
        devices -> Text,
    }
}

diesel::table! {
    queued_messages (id) {
        id -> BigInt,
        recipient -> Text,
        sender -> Nullable<Text>,
        data -> Binary,
    }
}

diesel::table! {
    ids (username) {
        username -> Text,
        user_certificate -> Binary,
    }
}

diesel::table! {
    devices (device_id) {
        device_id -> Text,
        device_certificate -> Binary,
        account -> Nullable<Text>,
    }
}