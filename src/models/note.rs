use crate::errors::{self, ServerError};
use crate::schema::notes;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use diesel::{Insertable, Queryable};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, Queryable, Serialize)]
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

impl QueryNote {
    pub fn decrypt(mut self, password: String) -> Result<Self, ServerError> {
        match self.password {
            Some(password_hash) => {
                let secret = std::env::var("SECRET_KEY")?;
                let parsed_hash = PasswordHash::new(&password_hash)?;
                let valid = Argon2::new_with_secret(
                    secret.as_bytes(),
                    Algorithm::default(),
                    Version::default(),
                    Params::default(),
                )?
                .verify_password(&password.as_bytes(), &parsed_hash)
                .is_ok();
                if valid {
                    let mc = new_magic_crypt!(password, 256);
                    self.content = mc.decrypt_base64_to_string(self.content)?;
                    self.password = None;
                    return Ok(self);
                } else {
                    return Err(ServerError::InvalidCred);
                }
            }
            None => {
                println!("Note ID {} is already decrypted", self.id);
                return Ok(self);
            }
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
    fn encrypt(mut self) -> Result<Self, ServerError> {
        match self.password {
            Some(password) => {
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
                self.encryption = true;
            }
            None => {
                self.password = None;
            }
        }

        Ok(self)
    }

    pub fn to_insertable(mut self) -> Result<InsertNote, ServerError> {
        if self.encryption && self.password.is_some() {
            self = self.encrypt()?;
        }

        let time_now = SystemTime::now();
        let expiry_time = match self.lifetime_in_secs {
            Some(duration) => {
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
