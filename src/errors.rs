use actix_web::HttpResponse;
use derive_more::Display;

#[derive(Debug, Display)]
pub enum ServerError {
    DieselError,
    EnvironmentError,
    R2D2Error,
    TinderCryptError,
    JWTError,
    Default,
    GeneralNoAccess,
    BlameUpdate,
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
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        println!("{e:?}");
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidToken
            | jsonwebtoken::errors::ErrorKind::InvalidSignature
            | jsonwebtoken::errors::ErrorKind::InvalidSubject => ServerError::GeneralNoAccess,
            jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(e) => {
                println!("Missing --> {e:?}");
                ServerError::BlameUpdate
            }
            _ => ServerError::JWTError,
        }
    }
}

impl From<std::string::FromUtf8Error> for ServerError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        println!("{e:?}");
        ServerError::Default
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
            ServerError::GeneralNoAccess => HttpResponse::Forbidden().body("Invalid token"),
            // leave this messageless
            ServerError::Default => HttpResponse::InternalServerError().finish(),
            ServerError::BlameUpdate => HttpResponse::UnprocessableEntity().body(
                "Irregular form of data: Possibly because of difference in app version and it's no longer supported",
            ),
        }
    }
}
