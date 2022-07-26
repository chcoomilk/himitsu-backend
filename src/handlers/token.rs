use std::time::SystemTime;

use super::note::Claims;
use crate::{errors::ServerError, Envar};
use actix_web::{post, put, web, HttpRequest, HttpResponse};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Deserialize;
use serde_json::json;

#[derive(Clone, Deserialize)]
pub struct TokenReq {
    token: String,
}

#[derive(Clone, Deserialize)]
struct Empty {}

#[post("")]
pub async fn verify(
    body: web::Json<TokenReq>,
    env: web::Data<Envar>,
) -> Result<HttpResponse, ServerError> {
    let mut validation = Validation::new(Algorithm::HS512);
    validation.required_spec_claims = std::collections::HashSet::new();
    validation.validate_exp = false;
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

#[put("")]
pub async fn combine(
    req: HttpRequest,
    body: web::Json<TokensReq>,
    env: web::Data<Envar>,
) -> Result<HttpResponse, ServerError> {
    let mut validation = Validation::new(Algorithm::HS512);
    validation.required_spec_claims = std::collections::HashSet::new();
    validation.validate_exp = false;
    let secret = env.secret.as_ref();
    let header = Header::new(Algorithm::HS512);
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
