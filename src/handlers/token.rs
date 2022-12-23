use std::time::SystemTime;

use super::{note::Claims, Pool};
use crate::{errors::ServerError, AppState};
use actix_web::{web, HttpRequest, HttpResponse};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey};
use serde::Deserialize;
use serde_json::json;

use crate::schema::notes::dsl::*;
use diesel::prelude::*;

#[derive(Clone, Deserialize)]
pub struct TokenReq {
    token: String,
}

#[derive(Clone, Deserialize)]
struct Empty {}

pub async fn verify(
    body: web::Json<TokenReq>,
    env: web::Data<AppState>,
) -> Result<HttpResponse, ServerError> {
    let validation = &env.jwt_validator;
    match decode::<Empty>(
        &body.token,
        &DecodingKey::from_secret(env.secret.as_ref()),
        &validation,
    ) {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(_) => Ok(HttpResponse::Unauthorized().finish()),
    }
}

#[derive(Clone, Deserialize)]
pub struct TokensReq {
    first_token: String,
    second_token: String,
}

pub async fn combine(
    req: HttpRequest,
    body: web::Json<TokensReq>,
    env: web::Data<AppState>,
) -> Result<HttpResponse, ServerError> {
    let validation = &env.jwt_validator;
    let header = &env.jwt_header;
    let secret = env.secret.as_ref();
    let original_token = decode::<Claims>(
        &body.first_token,
        &DecodingKey::from_secret(&secret),
        &validation,
    )?;
    let mut second_token = decode::<Claims>(
        &body.second_token,
        &DecodingKey::from_secret(&secret),
        &validation,
    )?;
    let mut token_data: Vec<(String, SystemTime)> = original_token
        .claims
        .ids
        .into_iter()
        .filter(|ot| {
            let res = second_token.claims.ids.iter().find(|&st| st.0 == ot.0);
            if let Some(st) = res {
                if ot.1 > st.1 {
                    true
                } else {
                    false
                }
            } else {
                true
            }
        })
        .collect();
    token_data.append(&mut second_token.claims.ids);
    let token = encode(
        &header,
        &Claims {
            iat: SystemTime::now(),
            ids: token_data,
            sub: req
                .connection_info()
                .peer_addr()
                .unwrap_or("unknown")
                .to_owned(),
        },
        &EncodingKey::from_secret(secret.as_ref()),
    )?;
    Ok(HttpResponse::Ok().json(json!({ "token": token })))
}

// this endpoint serves as clearing out ids that have been deleted
pub async fn refresh_token(
    req: HttpRequest,
    body: web::Json<TokenReq>,
    env: web::Data<AppState>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    let mut connection = pool.get()?;
    let validation = &env.jwt_validator;
    let header = &env.jwt_header;
    let secret: &[u8] = env.secret.as_ref();
    let token = decode::<Claims>(&body.token, &DecodingKey::from_secret(&secret), &validation)?;

    let mut result: Vec<(String, SystemTime)> = Vec::new();
    for _id in token.claims.ids.iter() {
        let should_push: bool = match notes
            .find(_id.0.to_owned())
            .select(created_at)
            .first::<SystemTime>(&mut connection)
        {
            Ok(creation_time) => {
                if creation_time == _id.1 {
                    true
                } else {
                    false
                }
            }
            Err(e) => match e {
                diesel::result::Error::NotFound => false,
                _ => {
                    return Err(ServerError::DieselError);
                }
            },
        };

        if should_push {
            result.push((_id.0.to_owned(), _id.1));
        }
    }

    let token = encode(
        &header,
        &Claims {
            iat: SystemTime::now(),
            ids: result,
            sub: req
                .connection_info()
                .peer_addr()
                .unwrap_or("unknown")
                .to_owned(),
        },
        &EncodingKey::from_secret(secret.as_ref()),
    )?;

    Ok(HttpResponse::Ok().json(json!({ "token": token })))
}
