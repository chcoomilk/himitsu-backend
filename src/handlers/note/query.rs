use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde_derive::Deserialize;
use serde_json::json;
use std::time::SystemTime;
use tindercrypt::cryptors::RingCryptor;

use super::{NoteInfo, Pool};

use crate::{errors::ServerError, schema::notes::dsl::*};

#[derive(Clone, Debug, Queryable)]
pub struct QueryNote {
    pub id: String,
    pub title: Option<String>,
    pub content: Vec<u8>,
    pub discoverable: bool,
    pub frontend_encryption: bool,
    pub backend_encryption: bool,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub delete_after_read: Option<i32>,
    pub allow_delete_with_passphrase: bool,
}

fn return_id_not_found_response(nid: String) -> HttpResponse {
    HttpResponse::NotFound().body(format!("note id: {} was not found", nid))
}

pub async fn info(
    note_id: web::Path<String>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let mut connection = pool.get()?;

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
        .get_result::<NoteInfo>(&mut connection)
    {
        Ok(note) => {
            if let Some(time) = note.expires_at {
                if time <= SystemTime::now() {
                    diesel::delete(notes.filter(id.eq(note_id.to_owned())))
                        .execute(&mut connection)?;
                    return Ok(return_id_not_found_response(note_id.to_owned()));
                }
            }

            Ok(HttpResponse::Ok().json(json!(note)))
        }
        Err(_) => Ok(return_id_not_found_response(note_id.to_owned())),
    }
}

#[derive(Deserialize)]
pub struct PassphraseField {
    pub passphrase: Option<String>,
}

#[derive(Deserialize)]
pub struct ReturnOption {
    pub secret_only: Option<bool>,
}

pub async fn decrypt_note(
    note_id: web::Path<String>,
    input: web::Json<PassphraseField>,
    query: web::Query<ReturnOption>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let mut connection = pool.get()?;
    // this error message has to be consistent so any bad actors will never know whether the note existed or not when requested

    match notes
        .find(note_id.to_owned())
        .get_result::<QueryNote>(&mut connection)
    {
        Ok(note) => {
            let note_content: String;
            let mut del_invalid_note =
                || match diesel::delete(notes.filter(id.eq(note_id.to_owned())))
                    .execute(&mut connection)
                {
                    Ok(_) => return_id_not_found_response(note_id.to_owned()),
                    Err(_) => HttpResponse::InternalServerError().finish(),
                };

            if let Some(time) = note.expires_at {
                if time <= SystemTime::now() {
                    return Ok(del_invalid_note());
                }
            }

            if note.backend_encryption {
                if let Some(passphrase) = &input.passphrase {
                    let cryptor = RingCryptor::new();
                    let res = cryptor.open(passphrase.as_bytes(), &note.content);

                    match res {
                        Ok(content_in_bytes) => note_content = String::from_utf8(content_in_bytes)?,
                        Err(err) => match err {
                            tindercrypt::errors::Error::PassphraseTooSmall => {
                                return Ok(HttpResponse::Unauthorized().body("wrong passphrase"));
                            }
                            tindercrypt::errors::Error::DecryptionError => {
                                return Ok(HttpResponse::Unauthorized().body("wrong passphrase"));
                            }
                            _ => {
                                return Err(ServerError::TinderCryptError);
                            }
                        },
                    }
                } else {
                    return Ok(HttpResponse::Unauthorized().body("wrong passphrase"));
                }
            } else {
                note_content = String::from_utf8(note.content)?;
            }

            if let Some(mut query_left) = note.delete_after_read {
                if query_left > 0 {
                    query_left -= 1;

                    diesel::update(notes.filter(id.eq(note_id.to_owned())))
                        .set(delete_after_read.eq(query_left))
                        .execute(&mut connection)?;
                } else {
                    diesel::delete(notes.filter(id.eq(note_id.to_owned())))
                        .execute(&mut connection)?;

                    return Ok(return_id_not_found_response(note_id.to_owned()));
                }
            }

            if query.secret_only.is_some().eq(&true) {
                return Ok(HttpResponse::Ok().json(json!({
                    "content": note_content,
                })));
            }

            Ok(HttpResponse::Ok().json(json!({
                "id": note.id,
                "title": note.title,
                "backend_encryption": note.backend_encryption,
                "frontend_encryption": note.frontend_encryption,
                "content": note_content,
                "created_at": note.created_at,
                "expires_at": note.expires_at,
                "request_left": note.delete_after_read.and_then(|x| Some(x-1)),
                "allow_delete_with_passphrase": note.allow_delete_with_passphrase,
            })))
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => Ok(return_id_not_found_response(note_id.to_owned())),
            _ => Err(ServerError::DieselError),
        },
    }
}

#[derive(Deserialize)]
pub struct FilterParameterQuery {
    pub title: String,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

pub async fn search_by_title(
    input: web::Query<FilterParameterQuery>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let mut connection = pool.get()?;

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
        .offset(input.0.offset.unwrap_or(0))
        .limit(input.0.limit.unwrap_or(5))
        .order(created_at.asc())
        .filter(
            title.ilike(&input.title).and(
                backend_encryption
                    .eq(false)
                    .and(frontend_encryption.eq(false))
                    .and(discoverable.eq(true)),
            ),
        )
        .get_results::<NoteInfo>(&mut connection)
    {
        Ok(notes_vec) => Ok(HttpResponse::Ok().json(json!(notes_vec))),
        Err(_) => Ok(HttpResponse::NotFound().finish()),
    }
}
