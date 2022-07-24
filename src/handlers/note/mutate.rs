use actix_web::{post, web, HttpResponse};
use diesel::prelude::*;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use nanoid::nanoid;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::time::{Duration, SystemTime};
use tindercrypt::cryptors::RingCryptor;

use super::{Claims, JWTAuth, NoteInfo, Pool};

use crate::{errors::ServerError, schema::notes::dsl::*, Envar};

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
    auth: web::Query<JWTAuth>,
    pool: web::Data<Pool>,
    env: web::Data<Envar>,
) -> Result<HttpResponse, ServerError> {
    let unwraped_token: Option<jsonwebtoken::TokenData<Claims>>;
    if let Some(token) = &auth.token {
        match decode::<Claims>(
            token,
            &DecodingKey::from_secret(env.secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        ) {
            Ok(token) => unwraped_token = Some(token),
            Err(e) => match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken
                | jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    return Ok(HttpResponse::Forbidden().body("Your token is not valid"));
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => unwraped_token = None,
                _ => {
                    println!("{}", e);
                    return Err(ServerError::JWTError);
                }
            },
        }
    } else {
        unwraped_token = None;
    }

    let time_now = SystemTime::now();
    let expiry_time = match input.lifetime_in_secs {
        Some(duration) => {
            // delete this if diesel can finally save some big length of time
            if duration > u32::MAX as u64 {
                return Ok(HttpResponse::InternalServerError().body(
                    "current amount of time is not supported, please put in lower length of time!",
                ));
            }
            //

            if duration > 30 {
                match time_now.checked_add(Duration::from_secs(duration)) {
                    Some(time) => Some(time),
                    None => {
                        return Ok(HttpResponse::InternalServerError().body(format!(
                            "time input resulting in duration of {} is too big and cannot be added into current time",
                            duration
                        )));
                    }
                }
            } else {
                return Ok(HttpResponse::BadRequest().body("time input is too short"));
            }
        }
        None => None,
    };

    let enc = (
        input.is_currently_encrypted.unwrap_or(false),
        input.passphrase.is_some(),
    );

    if input
        .discoverable
        .eq(&Some(true))
        .then(|| (enc.0 || enc.1))
        .eq(&Some(true))
    {
        return Ok(HttpResponse::BadRequest()
            .body("discoverability is not allowed if note is going to be encrypted"));
    }

    let content_bits: Vec<u8> = if let Some(passphrase) = &input.passphrase {
        let cryptor = RingCryptor::new();

        match cryptor.seal_with_passphrase(passphrase.as_bytes(), input.content.clone().as_bytes())
        {
            Ok(c) => c,
            Err(e) => match e {
                tindercrypt::errors::Error::PassphraseTooSmall => {
                    return Ok(HttpResponse::BadRequest().body("passphrase is too short"));
                }
                tindercrypt::errors::Error::BufferTooSmall => {
                    return Ok(HttpResponse::BadRequest().body("content body is too small"))
                }
                _ => return Err(ServerError::TinderCryptError),
            },
        }
    } else {
        input.content.clone().into_bytes()
    };

    let connection = pool.get()?;
    let append_id_token = move |new_id: String| match unwraped_token {
        Some(mut jwt) => {
            jwt.claims.ids.push(new_id);
            encode(
                &Header::default(),
                &jwt.claims,
                &EncodingKey::from_secret(env.secret.as_ref()),
            )
            .unwrap()
        }
        None => encode(
            &Header::default(),
            &Claims { ids: vec![new_id] },
            &EncodingKey::from_secret(env.secret.as_ref()),
        )
        .unwrap(),
    };

    if let Some(custom_id) = &input.id {
        let res = diesel::insert_into(notes)
            .values((
                &id.eq(custom_id),
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
                updated_at,
                created_at,
                expires_at,
            ))
            .get_results::<NoteInfo>(&connection);

        match res {
            Ok(result) => {
                let response = result[0].to_owned();

                Ok(HttpResponse::Created().json(json!({
                    "id": response.id,
                    "title": response.title,
                    "backend_encryption": response.backend_encryption,
                    "frontend_encryption": response.frontend_encryption,
                    "expires_at": response.expires_at,
                    "created_at": response.created_at,
                    "token": append_id_token(response.id)
                })))
            }
            Err(e) => match e {
                diesel::result::Error::DatabaseError(dbe_kind, _) => match dbe_kind {
                    diesel::result::DatabaseErrorKind::UniqueViolation => {
                        Ok(HttpResponse::Forbidden().body("id has been taken"))
                    }
                    _ => Err(ServerError::DieselError),
                },
                _ => Err(ServerError::DieselError),
            },
        }
    } else {
        let result: Result<HttpResponse, ServerError> = loop {
            let res = diesel::insert_into(notes)
                .values((
                    &id.eq(nanoid!(6)),
                    &title.eq(input.title.to_owned()),
                    &content.eq(&content_bits),
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
                    updated_at,
                    created_at,
                    expires_at,
                ))
                .get_results::<NoteInfo>(&connection);

            match res {
                Ok(result) => {
                    let response = result[0].to_owned();
                    break Ok(HttpResponse::Created().json(json!({
                        "id": response.id,
                        "title": response.title,
                        "backend_encryption": response.backend_encryption,
                        "frontend_encryption": response.frontend_encryption,
                        "expires_at": response.expires_at,
                        "created_at": response.created_at,
                        "token": append_id_token(response.id)
                    })));
                }
                Err(e) => match e {
                    diesel::result::Error::DatabaseError(dbe_kind, _) => match dbe_kind {
                        diesel::result::DatabaseErrorKind::UniqueViolation => {
                            continue;
                        }
                        _ => break Err(ServerError::DieselError),
                    },
                    _ => break Err(ServerError::DieselError),
                },
            }
        };

        result
    }
}

#[post("/{note_id}")]
pub async fn del(
    note_id: web::Path<String>,
    auth: web::Query<JWTAuth>,
    pool: web::Data<Pool>,
    env: web::Data<Envar>,
    // _req: web::HttpRequest,
) -> Result<HttpResponse, ServerError> {
    if let Some(token) = &auth.token {
        let jwt = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(env.secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        )?;

        if !jwt.claims.ids.contains(&note_id) {
            return Ok(HttpResponse::Unauthorized().finish());
        }
    } else {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    let connection = pool.get()?;

    match notes
        .select((
            id,
            title,
            backend_encryption,
            frontend_encryption,
            updated_at,
            created_at,
            expires_at,
        ))
        .find(note_id.to_owned())
        .first::<NoteInfo>(&connection)
    {
        Ok(note) => {
            diesel::delete(notes.filter(id.eq(&note.id))).execute(&connection)?;
            Ok(HttpResponse::Ok().json(json!({
                "id": note.id,
            })))
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => Ok(HttpResponse::NotFound().finish()),
            _ => Err(ServerError::DieselError),
        },
    }
}
