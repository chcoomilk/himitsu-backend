table! {
    notes (id) {
        id -> Varchar,
        title -> Varchar,
        content -> Bytea,
        discoverable -> Bool,
        frontend_encryption -> Bool,
        backend_encryption -> Bool,
        updated_at -> Timestamp,
        created_at -> Timestamp,
        expires_at -> Nullable<Timestamp>,
    }
}
