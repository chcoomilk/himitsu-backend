use actix_web::HttpResponse;
use derive_more::Display;
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Serialize)]
pub enum Error {
    TooShort,
    TooLong,
    Empty,
}

#[derive(Debug, Serialize)]
#[serde(rename_all(serialize = "snake_case"), tag = "field", content = "error")]
pub enum Fields {
    Content(Error),
    Password(Error),
    LifetimeInSecs(Error),
}

#[derive(Debug, Display)]
pub enum ServerError {
    ArgonError,
    DieselError,
    EnvironmentError,
    R2D2Error,
    MagicCryptError,
    InvalidCred,
    #[display(fmt = "Bad Request: {:?}", _0)]
    UserError(Vec<Fields>),
    #[display(fmt = "Not Found")]
    NotFound(String),
}

// impl std::fmt::Display for ServerError {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "Test")
//     }
// }

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

impl From<argon2::Error> for ServerError {
    fn from(_: argon2::Error) -> ServerError {
        ServerError::ArgonError
    }
}

impl From<argon2::password_hash::Error> for ServerError {
    fn from(_: argon2::password_hash::Error) -> ServerError {
        ServerError::ArgonError
    }
}

impl From<magic_crypt::MagicCryptError> for ServerError {
    fn from(_: magic_crypt::MagicCryptError) -> ServerError {
        ServerError::MagicCryptError
    }
}

impl actix_web::error::ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServerError::ArgonError => {
                HttpResponse::InternalServerError().json("Internal Error: Argon2 Error")
            }
            ServerError::DieselError => {
                HttpResponse::InternalServerError().json("Internal Error: Diesel Error.")
            }
            ServerError::EnvironmentError => {
                HttpResponse::InternalServerError().json("Internal Error: Environment Error.")
            }
            ServerError::R2D2Error => {
                HttpResponse::InternalServerError().json("Internal Error: Pooling Error.")
            }
            ServerError::MagicCryptError => {
                HttpResponse::InternalServerError().json("Internal Error: File Decryption Error")
            }
            ServerError::InvalidCred => {
                HttpResponse::Unauthorized().json(format!("Invalid Request: wrong credentials"))
            }
            ServerError::UserError(err) => HttpResponse::BadRequest().json(json!(err)),
            ServerError::NotFound(id) => HttpResponse::NotFound()
                .json(format!("Content with the id of: '{}' was not found", id)),
        }
    }
}
