use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde::Deserialize;
use serde_json::json;
use std::time::SystemTime;

use crate::errors::{self, ServerError};
use crate::models::note::{QueryNote, QueryNoteInfo, ReqNote, ResNote};
use crate::schema;
use crate::utils::is_password_valid;
use crate::Pool;

use schema::notes::{
    self,
    dsl::{encryption, expired_at, id, notes as table, title},
};

pub async fn new(
    input: web::Json<ReqNote>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;
    let uinput = input.0;
    let mut err_vec: Vec<errors::Fields> = Vec::new();

    {
        if uinput.content.is_empty() {
            err_vec.push(errors::Fields::Content(errors::Error::Empty));
        }

        if !err_vec.is_empty() {
            return Err(ServerError::UserError(err_vec));
        }
    }

    let res = diesel::insert_into(notes::table)
        .values(uinput.into_insert()?)
        .returning((id, title, encryption, expired_at))
        .get_results::<QueryNoteInfo>(&connection)?;
    Ok(HttpResponse::Created().json(json!(res)))
}

pub async fn get_info(
    web::Path(note_id): web::Path<i32>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    match table
        .select((id, title, encryption, expired_at))
        .filter(id.eq(note_id))
        .first::<QueryNoteInfo>(&connection)
    {
        Ok(note) => {
            if let Some(time) = note.expired_at {
                if time <= SystemTime::now() {
                    diesel::delete(table.filter(id.eq(note_id))).execute(&connection)?;
                    return Err(ServerError::NotFound(note_id.to_string()));
                }
            }

            Ok(HttpResponse::Ok().json(json!(note)))
        }
        Err(_) => Err(ServerError::NotFound(note_id.to_string())),
    }
}

#[derive(Deserialize)]
pub struct PasswordField {
    pub password: Option<String>,
}

pub async fn decrypt(
    web::Path(note_id): web::Path<i32>,
    input: web::Json<PasswordField>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let connection = pool.get()?;

    match table.find(note_id).get_result::<QueryNote>(&connection) {
        Ok(note) => {
            if let Some(time) = note.expired_at {
                if time <= SystemTime::now() {
                    diesel::delete(table.filter(id.eq(note_id))).execute(&connection)?;
                    return Err(ServerError::NotFound(note_id.to_string()));
                }
            }

            let result: ResNote = note.try_decrypt(input.0.password)?;

            Ok(HttpResponse::Ok().json(json!(result)))
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => Err(ServerError::NotFound(note_id.to_string())),
            _ => Err(ServerError::DieselError),
        },
    }
}

pub async fn del(
    web::Path(_note_id): web::Path<i32>,
    _input: web::Json<PasswordField>,
    _pool: web::Data<Pool>,
    _req: web::HttpRequest,
) -> Result<HttpResponse, ServerError> {
    let connection = _pool.get()?;
    // let token = get_token(req);
    // Ok(HttpResponse::Ok().json(token))

    match table.find(_note_id).get_result::<QueryNote>(&connection) {
        Ok(note) => {
            if let Some(password_hash) = note.password {
                if let Some(password) = &_input.0.password {
                    if !is_password_valid(password_hash, password)? {
                        return Err(ServerError::InvalidCred);
                    }
                } else {
                    return Err(ServerError::UserError(vec![errors::Fields::Password(
                        errors::Error::Empty,
                    )]));
                }
            }

            diesel::delete(table.filter(id.eq(note.id))).execute(&connection)?;
            Ok(HttpResponse::Ok().json(json!({
                "id": note.id,
            })))
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => Err(ServerError::NotFound(_note_id.to_string())),
            _ => Err(ServerError::DieselError),
        },
    }
}
