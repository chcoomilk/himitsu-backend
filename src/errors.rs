use actix_web::HttpResponse;
use derive_more::Display;

#[derive(Debug, Display)]
pub enum ServerError {
    DieselError,
    EnvironmentError,
    R2D2Error,
    TinderCryptError,
    JWTError,
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
    fn from(_: tindercrypt::errors::Error) -> ServerError {
        ServerError::TinderCryptError
    }
}

impl From<jsonwebtoken::errors::Error> for ServerError {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        ServerError::JWTError
    }
}

impl actix_web::error::ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServerError::DieselError => {
                HttpResponse::InternalServerError().body("Library Error: Diesel Error.")
            }
            ServerError::EnvironmentError => HttpResponse::InternalServerError()
                .body("Server Error: Use of an uninitialized environment variable."),
            ServerError::R2D2Error => {
                HttpResponse::InternalServerError().body("Server Error: Pooling Error.")
            }
            ServerError::TinderCryptError => HttpResponse::InternalServerError()
                .body("Library Error: File Decryption Unsucessful"),
            ServerError::JWTError => {
                HttpResponse::InternalServerError().body("Library Error: JWT Library Malfunctioned")
            }
        }
    }
}
