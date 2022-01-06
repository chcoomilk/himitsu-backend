use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde::Deserialize;
use serde_json::json;
use std::time::SystemTime;

use crate::errors::{self, ServerError};
use crate::models::note::{QueryNote, QueryNoteInfo, ReqNote};
use crate::schema;
use crate::Pool;

pub async fn new(
    input: web::Json<ReqNote>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use schema::notes::{
        self,
        dsl::{encryption, expired_at, id, title},
    };
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
        .values(uinput.to_insertable()?)
        .returning((id, title, encryption, expired_at))
        .get_results::<QueryNoteInfo>(&connection)?;
    Ok(HttpResponse::Created().json(json!(res)))
}

pub async fn get_info(
    web::Path(note_id): web::Path<i32>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use schema::notes::dsl::{encryption, expired_at, id, notes, title};
    let connection = pool.get()?;

    match notes
        .select((id, title, encryption, expired_at))
        .filter(id.eq(note_id))
        .first::<QueryNoteInfo>(&connection)
    {
        Ok(note) => {
            if let Some(time) = note.expired_at {
                if time <= SystemTime::now() {
                    diesel::delete(notes.filter(id.eq(note_id))).execute(&connection)?;
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
    pub password: String,
}

pub async fn get(
    web::Path(note_id): web::Path<i32>,
    input: web::Json<PasswordField>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use schema::notes::dsl::{id, notes};
    let connection = pool.get()?;

    match notes.find(note_id).get_result::<QueryNote>(&connection) {
        Ok(mut note) => {
            if let Some(time) = note.expired_at {
                if time <= SystemTime::now() {
                    diesel::delete(notes.filter(id.eq(note_id))).execute(&connection)?;
                    return Err(ServerError::NotFound(note_id.to_string()));
                }
            }

            if note.encryption {
                note = note.decrypt(input.password.clone())?;
            }

            Ok(HttpResponse::Ok().json(json!(note)))
        }
        Err(err) => match err {
            diesel::result::Error::NotFound => Err(ServerError::NotFound(note_id.to_string())),
            _ => Err(ServerError::DieselError),
        },
    }
}

// pub async fn del(
//   web::Path(note_id): web::Path<i32>,
//   pool: web::Data<Pool>,
//   req: web::HttpRequest,
// ) -> Result<HttpResponse, ServerError> {
//   if let Some(payload) = middlewares::auth(&req) {
//     use schema::notes::dsl::{id, notes, author};
//     let connection = pool.get().unwrap();
//     let res = delete(notes
//       .filter(id.eq(note_id))
//       .filter(author.eq(payload.id))
//     ).execute(&connection)?;
//     if res == 1 {
//       Ok(HttpResponse::Ok().json(format!("Successfully deleted: {}", note_id)))
//     } else {
//       Err(ServerError::UserError("Note does not exist"))
//     }
//   } else {
//     Err(ServerError::AccessDenied)
//   }
// }
