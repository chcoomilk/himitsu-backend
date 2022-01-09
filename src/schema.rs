table! {
    notes (id) {
        id -> Int4,
        title -> Varchar,
        content -> Varchar,
        password -> Nullable<Varchar>,
        encryption -> Bool,
        created_at -> Timestamp,
        expired_at -> Nullable<Timestamp>,
        updated_at -> Timestamp,
    }
}

table! {
    user_notes (id) {
        id -> Varchar,
        note_id -> Int4,
        user_id -> Int4,
        created_at -> Timestamp,
    }
}

table! {
    users (id) {
        id -> Int4,
        username -> Varchar,
        is_private -> Nullable<Bool>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

joinable!(user_notes -> notes (note_id));
joinable!(user_notes -> users (user_id));

allow_tables_to_appear_in_same_query!(
    notes,
    user_notes,
    users,
);
