use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde_derive::Deserialize;
use serde_json::json;
use std::time::SystemTime;

use crate::{
    errors::{self, ServerError},
    models::note::{NewNote, QueryNote, QueryNoteInfo, ResNote},
    schema,
};
use super::Pool;

use schema::notes::dsl::{backend_encryption, expired_at, frontend_encryption, id, notes, title};

pub async fn new(
    input: web::Json<NewNote>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;
    let uinput = input.0;
    let mut err_vec: Vec<errors::Fields> = Vec::new();

    {
        if uinput.content.is_empty() {
            err_vec.push(errors::Fields::Content(errors::CommonError::Empty));
        }

        if !err_vec.is_empty() {
            return Err(ServerError::UserError(err_vec));
        }
    }

    let result = diesel::insert_into(notes)
        .values(uinput.into_insert()?)
        .returning((
            id,
            title,
            backend_encryption,
            frontend_encryption,
            expired_at,
        ))
        .get_results::<QueryNoteInfo>(&connection)?;
    let response = result[0].to_owned().into_response();
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
        .filter(id.eq(note_id.to_owned()))
        .first::<QueryNoteInfo>(&connection)
    {
        Ok(note) => {
            if let Some(time) = note.expired_at {
                if time <= SystemTime::now() {
                    diesel::delete(notes.filter(id.eq(note_id.to_owned()))).execute(&connection)?;
                    return Err(ServerError::NotFound(note_id.to_string()));
                }
            }

            Ok(HttpResponse::Ok().json(json!(note.into_response())))
        }
        Err(_) => Err(ServerError::NotFound(note_id.to_string())),
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
                    return Err(ServerError::NotFound(note_id.to_string()));
                }
            }

            let result: ResNote = note.try_decrypt(input.0.passphrase)?;

            Ok(HttpResponse::Ok().json(json!(result)))
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => Err(ServerError::NotFound(note_id.to_string())),
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
            // if let Some(passphrase_hash) = note.passphrase {
            //     if let Some(passphrase_input) = &input.0.passphrase {
            //         if !is_passphrase_valid(&passphrase_hash, passphrase_input)? {
            //             return Err(ServerError::InvalidCredentials);
            //         }
            //     } else {
            //         return Err(ServerError::UserError(vec![errors::Fields::Passphrase(
            //             errors::CommonError::Empty,
            //         )]));
            //     }
            // }
            let res = note.try_decrypt(input.0.passphrase)?;
            diesel::delete(notes.filter(id.eq(res.id))).execute(&connection)?;
            Ok(HttpResponse::Ok().json(json!({
                "id": res.id,
            })))
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => Err(ServerError::NotFound(note_id.to_string())),
            _ => Err(ServerError::DieselError),
        },
    }
}
