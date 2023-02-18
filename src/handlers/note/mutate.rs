use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde_derive::{Deserialize};
use serde_json::json;
use tindercrypt::cryptors::RingCryptor;

use super::{Claims, JWTAuth, JWTAuthQuery, NoteInfo, Pool};

use crate::{errors::ServerError, schema::notes::dsl::*};

pub mod new;

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

    if auth.token.is_none() && json.passphrase.is_none() {
        return Ok(HttpResponse::Unauthorized().finish());
    }

    let note: NoteInfo = match notes
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
        Ok(n) => n,
        Err(err) => match err {
            diesel::result::Error::NotFound => return Ok(HttpResponse::NotFound().finish()),
            _ => return Err(ServerError::DieselError),
        },
    };

    if let Some(auth) = auth.0.unwrap() {
        let mut jwt = auth.decode()?;
        let res = jwt
            .claims
            .ids
            .iter()
            .enumerate()
            .find(|&t| t.1 .0.eq(&note_id.to_owned()));

        if let Some(res) = res {
            if note.created_at == res.1 .1 {
                diesel::delete(notes.filter(id.eq(&note.id))).execute(&mut connection)?;
                jwt.claims.ids.remove(res.0);
                return Ok(HttpResponse::Ok().json(json!({
                    "id": note.id,
                    "token": JWTAuth::new(jwt.claims)?,
                })));
            }
        }
    }

    if note.allow_delete_with_passphrase && json.passphrase.is_some() {
        let passphrase = json.passphrase.to_owned().unwrap();
        use crate::handlers::note::Validator;
        if passphrase.is_valid_passphrase() {
            let note_content = notes
                .select(content)
                .find(note_id.to_owned())
                .first::<Vec<u8>>(&mut connection)?;
            let cryptor = RingCryptor::new();
            let res = cryptor.open(passphrase.as_bytes(), &note_content);

            if res.is_ok() {
                diesel::delete(notes.filter(id.eq(&note.id.to_owned())))
                    .execute(&mut connection)?;
                return Ok(HttpResponse::Ok().finish());
            }
        }
    }

    Ok(HttpResponse::Unauthorized().finish())
}
