use crate::errors::{self, ServerError};
use crate::schema::notes;
use diesel::{Insertable, Queryable};
use serde_derive::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use tindercrypt::cryptors::RingCryptor;

// Non-sensitive way of getting a note
#[derive(Clone, Debug, Queryable, Serialize)]
pub struct NoteInfo {
    pub id: String,
    pub title: String,
    pub backend_encryption: bool,
    pub frontend_encryption: bool,
    pub expires_at: Option<SystemTime>,
    pub created_at: SystemTime,
}

// Raw note
#[derive(Clone, Debug, Queryable)]
pub struct QueryNote {
    pub id: String,
    pub title: String,
    pub content: Vec<u8>,
    pub discoverable: bool,
    pub frontend_encryption: bool,
    pub backend_encryption: bool,
    pub updated_at: SystemTime,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
}

// Turn into
#[derive(Clone, Serialize)]
pub struct ResNote {
    pub id: String,
    pub title: String,
    pub content: String,
    pub frontend_encryption: bool,
    pub backend_encryption: bool,
    pub updated_at: SystemTime,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
}

impl QueryNote {
    pub fn try_decrypt(&self, passphrase_input: &String) -> Result<ResNote, ServerError> {
        if self.backend_encryption {
            if !passphrase_input.is_empty() {
                if passphrase_input.len() < 4 || passphrase_input.len() >= 1024 {
                    Err(ServerError::InvalidCredentials)
                } else {
                    let cryptor = RingCryptor::new();
                    let content_in_bytes = cryptor.open(passphrase_input.as_bytes(), &self.content)?;
                    match String::from_utf8(content_in_bytes) {
                        Ok(content) => Ok(ResNote {
                            id: self.id.to_owned(),
                            title: self.title.to_owned(),
                            content,
                            frontend_encryption: self.frontend_encryption,
                            backend_encryption: true,
                            created_at: self.created_at,
                            updated_at: self.updated_at,
                            expires_at: self.expires_at,
                        }),
                        Err(_) => Err(ServerError::TinderCryptError),
                    }
                }
            } else {
                Err(ServerError::InvalidCredentials)
            }
        } else {
            Ok(ResNote {
                id: self.id.to_owned(),
                title: self.title.to_owned(),
                content: String::from_utf8(self.content.to_owned()).unwrap(),
                frontend_encryption: self.frontend_encryption,
                backend_encryption: false,
                created_at: self.created_at,
                updated_at: self.updated_at,
                expires_at: self.expires_at,
            })
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncomingNote {
    pub title: String,
    pub content: String,
    pub passphrase: Option<String>,
    pub is_currently_encrypted: bool,
    pub lifetime_in_secs: Option<u64>,
}

#[derive(Insertable)]
#[table_name = "notes"]
pub struct InsertableNote {
    pub title: String,
    pub content: Vec<u8>,
    pub frontend_encryption: bool,
    pub backend_encryption: bool,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub updated_at: SystemTime,
}

impl IncomingNote {
    pub fn into_insertable(self) -> Result<InsertableNote, ServerError> {
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

            Ok(InsertableNote {
                title: self.title.trim().to_string(),
                content: encrypted_content,
                backend_encryption: true,
                frontend_encryption: self.is_currently_encrypted,
                created_at: time_now,
                updated_at: time_now,
                expires_at: expiry_time,
            })
        } else {
            Ok(InsertableNote {
                title: self.title,
                content: self.content.into_bytes(),
                backend_encryption: false,
                frontend_encryption: self.is_currently_encrypted,
                created_at: time_now,
                updated_at: time_now,
                expires_at: expiry_time,
            })
        }
    }
}
