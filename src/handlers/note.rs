use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde::Deserialize;
use serde_json::json;
use std::time::SystemTime;

use crate::errors::{self, ServerError};
use crate::models::note::{QueryNote, ReqNote};
use crate::schema;
use crate::Pool;

pub async fn new(
    input: web::Form<ReqNote>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use schema::notes;
    let connection = pool.get()?;
    let uinput = input.0;
    let mut err_vec: Vec<errors::Fields> = Vec::new();

    {
        if uinput.content.is_empty() {
            err_vec.push(errors::Fields::Content(errors::Error::Empty));
        }

        if let Some(password) = &uinput.password {
            if 4 >= password.len() && uinput.encryption {
                err_vec.push(errors::Fields::Password(errors::Error::TooShort));
            }
        }

        if !err_vec.is_empty() {
            return Err(ServerError::UserError(err_vec));
        }
    }

    let res = diesel::insert_into(notes::table)
        .values(uinput.to_insertable()?)
        .get_result::<QueryNote>(&connection)?;
    Ok(HttpResponse::Created().json(json!({
      "id": res.id,
      "expired_at": res.expired_at
    })))
}

#[derive(Deserialize)]
pub struct PasswordField {
    pub password: String,
}

pub async fn get(
    web::Path(note_id): web::Path<i32>,
    input: web::Form<PasswordField>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use schema::notes::dsl::{id, notes};
    let connection = pool.get()?;
    let query = notes.filter(id.eq(note_id));
    match notes.find(note_id).get_result::<QueryNote>(&connection) {
        Ok(note) => {
            if let Some(time) = note.expired_at {
                if time <= SystemTime::now() {
                    diesel::delete(query).execute(&connection)?;
                    return Err(ServerError::NotFound(note_id.to_string()));
                }
            }
            let decrypted_note = note.decrypt(input.password.clone())?;
            Ok(HttpResponse::Ok().json(json!(decrypted_note)))
        }
        Err(_) => Err(ServerError::NotFound(note_id.to_string())),
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
