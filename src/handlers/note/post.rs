use actix_web::{post, web, HttpResponse};
use diesel::prelude::*;
use nanoid::nanoid;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::time::{Duration, SystemTime};
use tindercrypt::cryptors::RingCryptor;

use super::{
    errors,
    schema::notes::{
        backend_encryption, content, created_at, discoverable, dsl::notes, expires_at,
        frontend_encryption, id, title, updated_at,
    },
    NoteInfo, Pool, ServerError,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct NewNote {
    id: Option<String>,
    title: String,
    content: String,
    discoverable: Option<bool>,
    passphrase: Option<String>,
    is_currently_encrypted: Option<bool>,
    lifetime_in_secs: Option<u64>,
}

#[post("")]
pub async fn new(
    input: web::Json<NewNote>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    let time_now = SystemTime::now();
    let expiry_time = match input.lifetime_in_secs {
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

    let enc = (
        input.is_currently_encrypted.unwrap_or(false),
        input.passphrase.is_some(),
    );
    let mut security_err = vec![];
    if input
        .discoverable
        .eq(&Some(true))
        .then(|| (enc.0 || enc.1))
        .eq(&Some(true))
    {
        security_err.push(errors::Fields::LogicError(
            "Discoverability is not allowed if note is going to be encrypted",
        ));
    }

    let content_bits: Vec<u8> = if let Some(passphrase) = &input.passphrase {
        if passphrase.len() < 4 {
            security_err.push(errors::Fields::Passphrase(errors::CommonError::TooShort));
        } else if passphrase.len() >= 1024 {
            security_err.push(errors::Fields::Passphrase(errors::CommonError::TooLong));
        }

        let cryptor = RingCryptor::new();

        cryptor
            .seal_with_passphrase(passphrase.as_bytes(), input.content.clone().as_bytes())
            .unwrap()
    } else {
        input.content.clone().into_bytes()
    };

    if !security_err.is_empty() {
        return Err(ServerError::UserError(security_err));
    }

    let result = diesel::insert_into(notes)
        .values((
            &id.eq(input.id.to_owned().unwrap_or(nanoid!(6))),
            &title.eq(input.title.to_owned()),
            &content.eq(content_bits),
            &discoverable.eq(input.discoverable.unwrap_or(false)),
            &frontend_encryption.eq(enc.0),
            &backend_encryption.eq(enc.1),
            &updated_at.eq(time_now),
            &created_at.eq(time_now),
            &expires_at.eq(expiry_time),
        ))
        .returning((
            id,
            title,
            backend_encryption,
            frontend_encryption,
            expires_at,
            created_at,
        ))
        .get_results::<NoteInfo>(&connection)?;
    let response = result[0].to_owned();
    Ok(HttpResponse::Created().json(json!(response)))
}
