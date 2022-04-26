use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde_derive::Deserialize;
use serde_json::json;
use std::time::SystemTime;

use super::Pool;
use crate::{
    errors::{self, ServerError},
    models::note::{IncomingNewNote, NoteInfo, QueryNote, ResNote},
    schema,
};

use schema::notes::dsl::{backend_encryption, expired_at, frontend_encryption, id, notes, title};

pub async fn new(
    input: web::Json<IncomingNewNote>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;
    let uinput = input.0;
    let mut err_vec: Vec<errors::Fields> = Vec::new();

    if uinput.content.is_empty() {
        err_vec.push(errors::Fields::Content(errors::CommonError::Empty));
    }

    if !err_vec.is_empty() {
        return Err(ServerError::UserError(err_vec));
    }

    let result = diesel::insert_into(notes)
        .values(uinput.into_insertable()?)
        .returning((
            id,
            title,
            backend_encryption,
            frontend_encryption,
            expired_at,
        ))
        .get_results::<NoteInfo>(&connection)?;
    let response = result[0].to_owned();
    Ok(HttpResponse::Created().json(json!(response)))
}

pub async fn get_info(
    note_id: web::Path<i32>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    match notes
        .select((
            id,
            title,
            backend_encryption,
            frontend_encryption,
            expired_at,
        ))
        .find(note_id.to_owned())
        .get_result::<NoteInfo>(&connection)
    {
        Ok(note) => {
            if let Some(time) = note.expired_at {
                if time <= SystemTime::now() {
                    diesel::delete(notes.filter(id.eq(note_id.to_owned()))).execute(&connection)?;
                    return Err(ServerError::NotFound(Some(note_id.to_string())));
                }
            }

            Ok(HttpResponse::Ok().json(json!(note)))
        }
        Err(_) => Err(ServerError::NotFound(Some(note_id.to_string()))),
    }
}

#[derive(Deserialize)]
pub struct PassphraseField {
    pub passphrase: Option<String>,
}

pub async fn decrypt(
    note_id: web::Path<i32>,
    input: web::Json<PassphraseField>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    match notes
        .find(note_id.to_owned())
        .get_result::<QueryNote>(&connection)
    {
        Ok(note) => {
            if let Some(time) = note.expired_at {
                if time <= SystemTime::now() {
                    diesel::delete(notes.filter(id.eq(note_id.to_owned()))).execute(&connection)?;
                    return Err(ServerError::NotFound(Some(note_id.to_string())));
                }
            }

            let result: ResNote = note.try_decrypt(input.0.passphrase)?;

            Ok(HttpResponse::Ok().json(json!(result)))
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => {
                Err(ServerError::NotFound(Some(note_id.to_string())))
            }
            _ => Err(ServerError::DieselError),
        },
    }
}

pub async fn del(
    note_id: web::Path<i32>,
    input: web::Json<PassphraseField>,
    pool: web::Data<Pool>,
    // _req: web::HttpRequest,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    match notes
        .find(note_id.to_owned())
        .get_result::<QueryNote>(&connection)
    {
        Ok(note) => {
            let res = note.try_decrypt(input.0.passphrase)?;
            diesel::delete(notes.filter(id.eq(res.id))).execute(&connection)?;
            Ok(HttpResponse::Ok().json(json!({
                "id": res.id,
            })))
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => {
                Err(ServerError::NotFound(Some(note_id.to_string())))
            }
            _ => Err(ServerError::DieselError),
        },
    }
}

#[derive(Deserialize)]
pub struct TitleParameterQuery {
    pub title: String,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}
pub async fn get_by_title(
    input: web::Query<TitleParameterQuery>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    match notes
        .select((
            id,
            title,
            backend_encryption,
            frontend_encryption,
            expired_at,
        ))
        .offset(input.0.offset.unwrap_or(0))
        .limit(input.0.limit.unwrap_or(5))
        .order(id)
        .filter(title.ilike(&input.title))
        .get_results::<NoteInfo>(&connection)
    {
        Ok(notes_vec) => Ok(HttpResponse::Ok().json(json!(notes_vec))),
        Err(_) => Err(ServerError::NotFound(Some(input.title.clone()))),
    }
}

// pub async fn socket()
