use serde_derive::{Deserialize, Serialize};
use std::{collections::HashSet, time::SystemTime};

use super::Pool;

use jsonwebtoken::{
    self, decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub ids: Vec<(String, SystemTime)>,
    pub iat: SystemTime,
    pub sub: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWTAuthQuery {
    token: Option<String>,
}

impl JWTAuthQuery {
    fn unwrap(&self) -> Option<JWTAuth> {
        if let Some(token) = self.token.to_owned() {
            Some(JWTAuth { token })
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWTAuth {
    token: String,
}

impl JWTAuth {
    pub fn new(claims: Claims) -> Result<String, jsonwebtoken::errors::Error> {
        let header = Header::new(Algorithm::HS512);
        let secret = std::env::var("SECRET_KEY").unwrap();
        encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
    }

    pub fn decode(&self) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
        let secret = std::env::var("SECRET_KEY").unwrap();
        let mut validation = Validation::new(Algorithm::HS512);
        validation.required_spec_claims = HashSet::new();
        validation.validate_exp = false;
        decode::<Claims>(
            &self.token,
            &DecodingKey::from_secret(secret.as_ref()),
            &validation,
        )
    }
}

#[derive(Clone, Debug, Queryable, Serialize, PartialEq)]
struct NoteInfo {
    id: String,
    title: String,
    backend_encryption: bool,
    frontend_encryption: bool,
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
