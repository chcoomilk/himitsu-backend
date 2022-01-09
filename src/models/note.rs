use crate::errors::{self, ServerError};
use crate::schema::notes;
use crate::utils::is_password_valid;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use diesel::{Insertable, Queryable};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, Queryable, Serialize)]
pub struct QueryNoteInfo {
    pub id: i32,
    pub title: String,
    pub encryption: bool,
    pub expired_at: Option<SystemTime>,
}

// match this with table note in schema.rs
#[derive(Clone, Debug, Queryable)]
pub struct QueryNote {
    pub id: i32,
    pub title: String,
    pub content: String,
    pub password: Option<String>,
    pub encryption: bool,
    pub created_at: SystemTime,
    pub expired_at: Option<SystemTime>,
    pub updated_at: SystemTime,
}

#[derive(Clone, Serialize)]
pub struct ResNote {
    pub id: i32,
    pub title: String,
    pub content: String,
    pub decrypted: bool,
    pub created_at: SystemTime,
    pub expired_at: Option<SystemTime>,
    pub updated_at: SystemTime,
}

impl QueryNote {
    fn omit_fields(self, decrypted: bool) -> ResNote {
        return ResNote {
            id: self.id,
            title: self.title,
            content: self.content,
            decrypted,
            created_at: self.created_at,
            updated_at: self.updated_at,
            expired_at: self.expired_at,
        };
    }

    pub fn try_decrypt(mut self, password_input: Option<String>) -> Result<ResNote, ServerError> {
        if self.encryption {
            if let Some(password_hash) = self.password.clone() {
                if let Some(password) = password_input {
                    if password.len() < 4 {
                        return Err(ServerError::UserError(vec![errors::Fields::Password(
                            errors::Error::TooShort,
                        )]));
                    }

                    if is_password_valid(password_hash, &password)? {
                        let mc = new_magic_crypt!(password, 256);
                        self.content = mc.decrypt_base64_to_string(self.content)?;
                    } else {
                        return Err(ServerError::InvalidCred);
                    }

                    Ok(self.omit_fields(true))
                } else {
                    return Err(ServerError::UserError(vec![errors::Fields::Password(
                        errors::Error::Empty,
                    )]));
                }
            } else {
                Ok(self.omit_fields(false))
            }
        } else {
            Ok(self.omit_fields(true))
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReqNote {
    pub title: String,
    pub content: String,
    pub password: Option<String>,
    pub encryption: bool,
    pub lifetime_in_secs: Option<u64>,
}

#[derive(Insertable)]
#[table_name = "notes"]
pub struct InsertNote {
    pub title: String,
    pub content: String,
    pub encryption: bool,
    pub password: Option<String>,
    pub created_at: SystemTime,
    pub expired_at: Option<SystemTime>,
    pub updated_at: SystemTime,
}

impl ReqNote {
    fn encrypt(mut self, password: String) -> Result<Self, ServerError> {
        if password.len() < 4 {
            return Err(ServerError::UserError(vec![errors::Fields::Password(
                errors::Error::TooShort,
            )]));
        }

        let secret = std::env::var("SECRET_KEY")?;

        let mc = new_magic_crypt!(&password, 256);

        let hashed_password = Argon2::new_with_secret(
            secret.as_bytes(),
            Algorithm::default(),
            Version::default(),
            Params::default(),
        )?
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))?
        .to_string();

        self.content = mc.encrypt_str_to_base64(self.content);
        self.password = Some(hashed_password);

        Ok(self)
    }

    pub fn into_insert(mut self) -> Result<InsertNote, ServerError> {
        let time_now = SystemTime::now();
        let expiry_time = match self.lifetime_in_secs {
            Some(duration) => {
                // delete this if diesel can finally save some big length of date
                if duration > u32::MAX as u64 {
                    return Err(ServerError::UserError(vec![
                        errors::Fields::LifetimeInSecs(errors::Error::TooLong),
                    ]));
                }
                //

                if duration > 30 {
                    match time_now.checked_add(Duration::from_secs(duration)) {
                        Some(time) => Some(time),
                        None => {
                            return Err(ServerError::UserError(vec![
                                errors::Fields::LifetimeInSecs(errors::Error::TooLong),
                            ]));
                        }
                    }
                } else {
                    return Err(ServerError::UserError(vec![
                        errors::Fields::LifetimeInSecs(errors::Error::TooShort),
                    ]));
                }
            }
            None => None,
        };

        if self.encryption {
            if let Some(password) = self.password.clone() {
                self = self.encrypt(password)?;
            }
        } else {
            self.password = None;
        }

        Ok(InsertNote {
            title: self.title,
            content: self.content,
            encryption: self.encryption,
            password: self.password,
            created_at: time_now,
            updated_at: time_now,
            expired_at: expiry_time,
        })
    }
}
