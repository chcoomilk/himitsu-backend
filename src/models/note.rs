use crate::errors::{self, ServerError};
use crate::schema::notes;
use diesel::{Insertable, Queryable};
use serde_derive::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use tindercrypt::cryptors::RingCryptor;

#[derive(Clone, Debug, Queryable)]
pub struct QueryNoteInfo {
    pub id: i32,
    pub title: String,
    pub backend_encryption: bool,
    pub frontend_encryption: bool,
    pub expired_at: Option<SystemTime>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResNoteInfo {
    pub id: i32,
    pub title: String,
    pub frontend_encryption: bool,
    pub backend_encryption: bool,
    // pub updated_at: SystemTime,
    // pub created_at: SystemTime,
    pub expired_at: Option<SystemTime>,
}

impl QueryNoteInfo {
    pub fn into_response(self) -> ResNoteInfo {
        ResNoteInfo {
            id: self.id,
            title: self.title,
            backend_encryption: self.backend_encryption,
            frontend_encryption: self.frontend_encryption,
            expired_at: self.expired_at,
        }
    }
}

// match this with table note in schema.rs
#[derive(Clone, Debug, Queryable)]
pub struct QueryNote {
    pub id: i32,
    pub title: String,
    pub content: Vec<u8>,
    pub frontend_encryption: bool,
    pub backend_encryption: bool,
    pub updated_at: SystemTime,
    pub created_at: SystemTime,
    pub expired_at: Option<SystemTime>,
}

#[derive(Clone, Serialize)]
pub struct ResNote {
    pub id: i32,
    pub title: String,
    pub content: String,
    pub frontend_encryption: bool,
    pub backend_encryption: bool,
    pub updated_at: SystemTime,
    pub created_at: SystemTime,
    pub expired_at: Option<SystemTime>,
}

impl QueryNote {
    pub fn try_decrypt(self, passphrase_input: Option<String>) -> Result<ResNote, ServerError> {
        if self.backend_encryption {
            if let Some(passphrase) = passphrase_input {
                if passphrase.len() < 4 || passphrase.len() >= 1024 {
                    Err(ServerError::InvalidCredentials)
                } else {
                    let cryptor = RingCryptor::new();
                    let content_in_bytes = cryptor.open(passphrase.as_bytes(), &self.content)?;
                    match String::from_utf8(content_in_bytes) {
                        Ok(content) => Ok(ResNote {
                            id: self.id,
                            title: self.title,
                            content,
                            frontend_encryption: self.frontend_encryption,
                            backend_encryption: true,
                            created_at: self.created_at,
                            updated_at: self.updated_at,
                            expired_at: self.expired_at,
                        }),
                        Err(_) => Err(ServerError::TinderCryptError),
                    }
                }
            } else {
                Err(ServerError::InvalidCredentials)
            }
        } else {
            Ok(ResNote {
                id: self.id,
                title: self.title,
                content: String::from_utf8(self.content).unwrap(),
                frontend_encryption: self.frontend_encryption,
                backend_encryption: false,
                created_at: self.created_at,
                updated_at: self.updated_at,
                expired_at: self.expired_at,
            })
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NewNote {
    pub title: String,
    pub content: String,
    pub passphrase: Option<String>,
    pub is_currently_encrypted: bool,
    pub lifetime_in_secs: Option<u64>,
}

#[derive(Insertable)]
#[table_name = "notes"]
pub struct InsertNote {
    pub title: String,
    pub content: Vec<u8>,
    pub frontend_encryption: bool,
    pub backend_encryption: bool,
    pub created_at: SystemTime,
    pub expired_at: Option<SystemTime>,
    pub updated_at: SystemTime,
}

impl NewNote {
    pub fn into_insert(self) -> Result<InsertNote, ServerError> {
        let time_now = SystemTime::now();
        let expiry_time = match self.lifetime_in_secs {
            Some(duration) => {
                // delete this if diesel can finally save some big length of time
                if duration > u32::MAX as u64 {
                    return Err(ServerError::UserError(vec![
                        errors::Fields::LifetimeInSecs(errors::CommonError::TooLong),
                    ]));
                }
                //

                if duration > 30 {
                    match time_now.checked_add(Duration::from_secs(duration)) {
                        Some(time) => Some(time),
                        None => {
                            return Err(ServerError::UserError(vec![
                                errors::Fields::LifetimeInSecs(errors::CommonError::TooLong),
                            ]));
                        }
                    }
                } else {
                    return Err(ServerError::UserError(vec![
                        errors::Fields::LifetimeInSecs(errors::CommonError::TooShort),
                    ]));
                }
            }
            None => None,
        };

        if let Some(passphrase) = self.passphrase.clone() {
            if passphrase.len() < 4 {
                return Err(ServerError::UserError(vec![errors::Fields::Passphrase(
                    errors::CommonError::TooShort,
                )]));
            } else if passphrase.len() >= 1024 {
                return Err(ServerError::UserError(vec![errors::Fields::Passphrase(
                    errors::CommonError::TooLong,
                )]));
            }

            let cryptor = RingCryptor::new();

            let encrypted_content = cryptor
                .seal_with_passphrase(passphrase.as_bytes(), self.content.as_bytes())
                .unwrap();

            Ok(InsertNote {
                title: self.title,
                content: encrypted_content,
                backend_encryption: true,
                frontend_encryption: self.is_currently_encrypted,
                created_at: time_now,
                updated_at: time_now,
                expired_at: expiry_time,
            })
        } else {
            Ok(InsertNote {
                title: self.title,
                content: self.content.into_bytes(),
                backend_encryption: false,
                frontend_encryption: self.is_currently_encrypted,
                created_at: time_now,
                updated_at: time_now,
                expired_at: expiry_time,
            })
        }
    }
}
