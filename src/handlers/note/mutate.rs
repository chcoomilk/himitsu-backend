use actix_web::{web, HttpRequest, HttpResponse};
use diesel::prelude::*;
use nanoid::nanoid;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::time::{Duration, SystemTime};
use tindercrypt::cryptors::RingCryptor;

use super::{Claims, JWTAuth, JWTAuthQuery, NoteInfo, Pool};

use crate::{errors::ServerError, schema::notes::dsl::*};

#[derive(Clone, Deserialize, Serialize)]
pub struct NewNote {
    id: Option<String>,
    title: Option<String>,
    content: String,
    discoverable: Option<bool>,
    passphrase: Option<String>,
    is_currently_encrypted: Option<bool>,
    lifetime_in_secs: Option<u64>,
    delete_after_read: Option<i32>,
    allow_delete_with_passphrase: Option<bool>,
}

pub async fn new(
    req: HttpRequest,
    input: web::Json<NewNote>,
    auth: web::Query<JWTAuthQuery>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let unwraped_token: Option<jsonwebtoken::TokenData<Claims>>;
    if let Some(token) = &auth.unwrap() {
        match token.decode() {
            Ok(token) => unwraped_token = Some(token),
            Err(e) => match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken
                | jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    return Ok(HttpResponse::Forbidden().body("Your token is not valid"));
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => unwraped_token = None,
                _ => {
                    log::error!("{e}");
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

    if let Some(t) = &input.title {
        if t.trim().is_empty() {
            return Ok(HttpResponse::BadRequest().body("title is empty"));
        } else {
            if t.len() <= 3 {
                return Ok(HttpResponse::BadRequest().body("title is too short"));
            }
        }
    }

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

    let mut connection = pool.get()?;
    let append_id_token = move |new_id: String, c: SystemTime| match unwraped_token {
        Some(mut jwt) => {
            jwt.claims.ids.retain(|t| t.0 != new_id);
            jwt.claims.ids.push((new_id, c));
            JWTAuth::new(Claims {
                ids: jwt.claims.ids,
                iat: SystemTime::now(),
                sub: req
                    .connection_info()
                    .peer_addr()
                    .unwrap_or("unknown")
                    .to_string(),
            })
        }
        None => JWTAuth::new(Claims {
            ids: vec![(new_id, c)],
            iat: SystemTime::now(),
            sub: req
                .connection_info()
                .peer_addr()
                .unwrap_or("unknown")
                .to_string(),
        }),
    };

    let mut insert_note = |_id: String| {
        diesel::insert_into(notes)
            .values((
                &id.eq(_id),
                &title.eq(input.title.to_owned()),
                &content.eq(&content_bits),
                &discoverable.eq(input.discoverable.unwrap_or(false)),
                &frontend_encryption.eq(enc.0),
                &backend_encryption.eq(enc.1),
                &created_at.eq(time_now),
                &expires_at.eq(expiry_time),
                &delete_after_read.eq(input.delete_after_read),
                &allow_delete_with_passphrase
                    .eq(input.allow_delete_with_passphrase.unwrap_or(false)),
            ))
            .returning((
                id,
                title,
                backend_encryption,
                frontend_encryption,
                created_at,
                expires_at,
                delete_after_read,
                allow_delete_with_passphrase,
            ))
            .get_results::<NoteInfo>(&mut connection)
    };

    if let Some(custom_id) = &input.id {
        if !custom_id.trim().is_empty() {
            let res = insert_note(custom_id.to_owned());

            match res {
                Ok(result) => {
                    let response = result[0].to_owned();
                    let token = append_id_token(response.id.clone(), response.created_at);
                    if token.is_err() {
                        diesel::delete(notes)
                            .filter(id.eq(&response.id))
                            .execute(&mut connection)?;
                    }
                    return Ok(HttpResponse::Created().json(json!({
                        "id": response.id,
                        "title": response.title,
                        "backend_encryption": response.backend_encryption,
                        "frontend_encryption": response.frontend_encryption,
                        "expires_at": response.expires_at,
                        "created_at": response.created_at,
                        "token": token?
                    })));
                }
                Err(e) => match e {
                    diesel::result::Error::DatabaseError(dbe_kind, _) => match dbe_kind {
                        diesel::result::DatabaseErrorKind::UniqueViolation => {
                            return Ok(HttpResponse::Conflict().body("id has been taken"));
                        }
                        _ => {
                            return Err(ServerError::DieselError);
                        }
                    },
                    _ => {
                        return Err(ServerError::DieselError);
                    }
                },
            }
        }
    }

    // good idea to check if this ever goes on forever because 6-long id is exhausted
    // but nah
    let result: Result<HttpResponse, ServerError> = loop {
        let res = insert_note(nanoid!(6));

        match res {
            Ok(result) => {
                let response = result[0].to_owned();
                let token = append_id_token(response.id.clone(), response.created_at);
                if token.is_err() {
                    diesel::delete(notes)
                        .filter(id.eq(&response.id))
                        .execute(&mut connection)?;
                }
                break Ok(HttpResponse::Created().json(json!({
                    "id": response.id,
                    "title": response.title,
                    "backend_encryption": response.backend_encryption,
                    "frontend_encryption": response.frontend_encryption,
                    "expires_at": response.expires_at,
                    "created_at": response.created_at,
                    "token": token?
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

#[derive(Deserialize)]
pub struct WithPassphrase {
    passphrase: Option<String>,
}

pub async fn del(
    note_id: web::Path<String>,
    auth: web::Query<JWTAuthQuery>,
    json: web::Json<WithPassphrase>,
    pool: web::Data<Pool>,
    // _req: web::HttpRequest,
) -> Result<HttpResponse, ServerError> {
    let mut connection = pool.get()?;

    if let Some(auth) = auth.0.unwrap() {
        let mut jwt = auth.decode()?;
        let res = jwt
            .claims
            .ids
            .iter()
            .enumerate()
            .find(|&t| t.1 .0.eq(&note_id.to_owned()));

        if let Some(res) = res {
            match notes
                .select((
                    id,
                    title,
                    backend_encryption,
                    frontend_encryption,
                    created_at,
                    expires_at,
                    delete_after_read,
                    allow_delete_with_passphrase,
                ))
                .find(note_id.to_owned())
                .first::<NoteInfo>(&mut connection)
            {
                Ok(note) => {
                    if note.created_at == res.1 .1 {
                        diesel::delete(notes.filter(id.eq(&note.id))).execute(&mut connection)?;
                        jwt.claims.ids.remove(res.0);
                        return Ok(HttpResponse::Ok().json(json!({
                            "id": note.id,
                            "token": JWTAuth::new(jwt.claims)?,
                        })));
                    }
                }
                Err(err) => match err {
                    diesel::result::Error::NotFound => return Ok(HttpResponse::NotFound().finish()),
                    _ => return Err(ServerError::DieselError),
                },
            }
        }
    }

    use crate::handlers::note::Validator;
    if let Some(passphrase) = &json.0.passphrase {
        if passphrase.is_valid_passphrase() {
            let note_content = notes
                .select(content)
                .find(note_id.to_owned())
                .first::<Vec<u8>>(&mut connection)?;
            let cryptor = RingCryptor::new();
            let res = cryptor.open(passphrase.as_bytes(), &note_content);

            if res.is_ok() {
                diesel::delete(notes.filter(id.eq(&note_id.to_owned())))
                    .execute(&mut connection)?;
                return Ok(HttpResponse::Ok().finish());
            }
        }
    }

    Ok(HttpResponse::Unauthorized().finish())
}
