use actix_web::HttpResponse;
use derive_more::Display;
use serde_derive::Serialize;
use serde_json::json;

#[derive(Debug, Serialize)]
pub enum CommonError {
    TooShort,
    TooLong,
    Empty,
}

#[derive(Debug, Serialize)]
#[serde(rename_all(serialize = "snake_case"), tag = "field", content = "error")]
pub enum Fields {
    Content(CommonError),
    Passphrase(CommonError),
    LifetimeInSecs(CommonError),
}

#[derive(Debug, Display)]
pub enum ServerError {
    DieselError,
    EnvironmentError,
    R2D2Error,
    TinderCryptError,
    InvalidCredentials,
    #[display(fmt = "Bad Request: {:?}", _0)]
    UserError(Vec<Fields>),
    #[display(fmt = "Not Found")]
    NotFound(Option<String>),
}

impl From<r2d2::Error> for ServerError {
    fn from(_: r2d2::Error) -> ServerError {
        ServerError::R2D2Error
    }
}

impl From<std::env::VarError> for ServerError {
    fn from(_: std::env::VarError) -> ServerError {
        ServerError::EnvironmentError
    }
}

impl From<diesel::result::Error> for ServerError {
    fn from(_: diesel::result::Error) -> ServerError {
        ServerError::DieselError
    }
}

impl From<tindercrypt::errors::Error> for ServerError {
    fn from(err: tindercrypt::errors::Error) -> ServerError {
        match err {
            tindercrypt::errors::Error::DecryptionError => ServerError::InvalidCredentials,
            _ => ServerError::TinderCryptError
        }
    }
}

impl actix_web::error::ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServerError::DieselError => {
                HttpResponse::InternalServerError().body("Internal Error: Diesel Error.")
            }
            ServerError::EnvironmentError => {
                HttpResponse::InternalServerError().body("Internal Error: Environment Error.")
            }
            ServerError::R2D2Error => {
                HttpResponse::InternalServerError().body("Internal Error: Pooling Error.")
            }
            ServerError::TinderCryptError => {
                HttpResponse::InternalServerError().body("Internal Error: File Decryption Error")
            }
            ServerError::InvalidCredentials => HttpResponse::Unauthorized().json(json!({
                "error": "possibly wrong passphrase"
            })),
            ServerError::UserError(err) => HttpResponse::BadRequest().json(json!(err)),
            ServerError::NotFound(keyword) => HttpResponse::NotFound().json(json!({
                "query": keyword.as_ref().unwrap_or(&"Empty Set".to_string()),
            })),
        }
    }
}
