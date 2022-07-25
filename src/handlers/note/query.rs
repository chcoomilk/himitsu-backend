use actix_web::{get, post, web, HttpResponse};
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
    pub title: String,
    pub content: Vec<u8>,
    pub discoverable: bool,
    pub frontend_encryption: bool,
    pub backend_encryption: bool,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
}

#[get("/{note_id}")]
pub async fn info(
    note_id: web::Path<String>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    match notes
        .select((
            id,
            title,
            backend_encryption,
            frontend_encryption,
            created_at,
            expires_at,
        ))
        .find(note_id.to_owned())
        .get_result::<NoteInfo>(&connection)
    {
        Ok(note) => {
            if let Some(time) = note.expires_at {
                if time <= SystemTime::now() {
                    diesel::delete(notes.filter(id.eq(note_id.to_owned()))).execute(&connection)?;
                    return Ok(HttpResponse::NotFound()
                        .body(format!("note id: {} was not found", note_id)));
                }
            }

            Ok(HttpResponse::Ok().json(json!(note)))
        }
        Err(_) => Ok(HttpResponse::NotFound().body(format!("note id: {} was not found", note_id))),
    }
}

#[derive(Deserialize)]
pub struct PassphraseField {
    pub passphrase: Option<String>,
}

#[post("/{note_id}")]
pub async fn decrypt_note(
    note_id: web::Path<String>,
    input: web::Json<PassphraseField>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    match notes
        .find(note_id.to_owned())
        .get_result::<QueryNote>(&connection)
    {
        Ok(note) => {
            if let Some(time) = note.expires_at {
                if time <= SystemTime::now() {
                    diesel::delete(notes.filter(id.eq(note_id.to_owned()))).execute(&connection)?;
                    return Ok(HttpResponse::NotFound()
                        .body(format!("note id: {} was not found", note_id)));
                }
            }

            if note.backend_encryption {
                if let Some(passphrase) = &input.passphrase {
                    let cryptor = RingCryptor::new();
                    let res = cryptor.open(passphrase.as_bytes(), &note.content);
                    match res {
                        Ok(content_in_bytes) => match String::from_utf8(content_in_bytes) {
                            Ok(note_content) => Ok(HttpResponse::Ok().json(json!({
                                "id": note.id,
                                "title": note.title,
                                "backend_encryption": note.backend_encryption,
                                "frontend_encryption": note.frontend_encryption,
                                "content": note_content,
                                "created_at": note.created_at,
                                "expires_at": note.expires_at,
                            }))),
                            Err(_) => Err(ServerError::TinderCryptError),
                        },
                        Err(err) => match err {
                            tindercrypt::errors::Error::PassphraseTooSmall => {
                                Ok(HttpResponse::Unauthorized().body("wrong passphrase"))
                            }
                            tindercrypt::errors::Error::DecryptionError => {
                                Ok(HttpResponse::Unauthorized().body("wrong passphrase"))
                            }
                            _ => Err(ServerError::TinderCryptError),
                        },
                    }
                } else {
                    Ok(HttpResponse::Unauthorized().body("wrong passphrase"))
                }
            } else {
                let note_content = String::from_utf8(note.content)?;
                Ok(HttpResponse::Ok().json(json!({
                    "id": note.id,
                    "title": note.title,
                    "backend_encryption": note.backend_encryption,
                    "frontend_encryption": note.frontend_encryption,
                    "content": note_content,
                    "created_at": note.created_at,
                    "expires_at": note.expires_at,
                })))
            }
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => {
                Ok(HttpResponse::NotFound().body(format!("note id: {} was not found", note_id)))
            }
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

#[get("")]
pub async fn search_by_title(
    input: web::Query<FilterParameterQuery>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    match notes
        .select((
            id,
            title,
            backend_encryption,
            frontend_encryption,
            created_at,
            expires_at,
        ))
        .offset(input.0.offset.unwrap_or(0))
        .limit(input.0.limit.unwrap_or(5))
        .order(id)
        .filter(
            title.ilike(&input.title).and(
                backend_encryption
                    .eq(false)
                    .and(frontend_encryption.eq(false))
                    .and(discoverable.eq(true)),
            ),
        )
        .get_results::<NoteInfo>(&connection)
    {
        Ok(notes_vec) => Ok(HttpResponse::Ok().json(json!(notes_vec))),
        Err(_) => Ok(HttpResponse::NotFound().finish()),
    }
}
