use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde_json::json;
use std::time::{SystemTime};

use crate::models::plain_note::{PlainNote, ReqPlainNote};
use crate::schema;
use crate::Pool;
use crate::ServerError;

pub async fn new(
    input: web::Form<ReqPlainNote>,
    pool: web::Data<Pool>
) -> Result<HttpResponse, ServerError> {
    use schema::plain_notes;
    let connection = pool.get()?;
    let note = input.0.to_insertable()?;
    let res = diesel::insert_into(plain_notes::table)
        .values(note)
        .get_result::<PlainNote>(&connection)?;
    Ok(HttpResponse::Created().json(json!({
      "id": res.id,
      "expired_at": res.expired_at
    })))
}

pub async fn get(
    web::Path(note_id): web::Path<String>,
    pool: web::Data<Pool>
) -> Result<HttpResponse, ServerError> {
    use schema::plain_notes::dsl::plain_notes;
    let connection = pool.get()?;

    let res = plain_notes.find(&note_id).get_result::<PlainNote>(&connection);
    match res {
        Ok(note) => {
            if note.expired_at <= SystemTime::now() {
                diesel::delete(plain_notes.filter(schema::plain_notes::id.eq(&note_id))).execute(&connection)?;
                return Err(ServerError::NotFound(note_id.to_string()));
            }

            Ok(HttpResponse::Ok().json(json!(note)))
        }
        Err(_) => Err(ServerError::NotFound(note_id.to_string()))
    }
}