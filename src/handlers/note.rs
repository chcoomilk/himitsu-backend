use serde_derive::{Deserialize, Serialize};
use std::time::SystemTime;

use super::Pool;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    ids: Vec<String>,
}

#[derive(Clone, Debug, Queryable, Serialize, Deserialize)]
pub struct JWTAuth {
    token: Option<String>,
}

#[derive(Clone, Debug, Queryable, Serialize, PartialEq)]
struct NoteInfo {
    id: String,
    title: String,
    backend_encryption: bool,
    frontend_encryption: bool,
    updated_at: SystemTime,
    created_at: SystemTime,
    expires_at: Option<SystemTime>,
}

trait Validator {
    fn is_valid_passphrase(&self) -> bool;
}

impl Validator for String {
    fn is_valid_passphrase(&self) -> bool {
        if &self.len() < &4 {
            return false;
        } else if &self.len() >= &1024 {
            return false;
        }

        true
    }
}

pub mod mutate;
pub mod query;

// pub async fn socket()
