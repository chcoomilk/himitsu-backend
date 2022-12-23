table! {
    notes (id) {
        id -> Varchar,
        title -> Nullable<Varchar>,
        content -> Bytea,
        discoverable -> Bool,
        frontend_encryption -> Bool,
        backend_encryption -> Bool,
        created_at -> Timestamp,
        expires_at -> Nullable<Timestamp>,
        delete_after_read -> Nullable<Int4>,
        allow_delete_with_passphrase -> Bool,
    }
}
