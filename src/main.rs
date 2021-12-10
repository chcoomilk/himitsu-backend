use std::time::SystemTime;

use actix_cors::Cors;
use actix_ratelimit::{MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[macro_use]
extern crate diesel;

mod handlers;
mod models;
mod schema;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    std::env::var("SECRET_KEY").expect("env SECRET_KEY");
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let port = std::env::var("PORT").expect("env PORT");
    let database_url = std::env::var("DATABASE_URL").expect("env DATABASE_URL");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("failed to create a pg pool");
    let connection = pool.get().unwrap();
    let store = MemoryStore::new();
    let interval = std::env::var("CLEANUP_INTERVAL")
        .unwrap_or("2700".to_string())
        .parse::<u64>()
        .expect("CLEANUP_INTERVAL must be postive integer");

    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        use schema::notes::dsl::notes;
        use schema::plain_notes::dsl::plain_notes;
        println!("cleaning");
        diesel::delete(notes.filter(schema::notes::expired_at.le(SystemTime::now())))
            .execute(&connection)
            .unwrap();
        diesel::delete(plain_notes.filter(schema::plain_notes::expired_at.le(SystemTime::now())))
            .execute(&connection)
            .unwrap();
    });

    HttpServer::new(move || {
        App::new()
            .data(pool.clone())
            .route("/", web::get().to(handlers::index))
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
                    .max_age(3600),
            )
            .wrap(
                RateLimiter::new(MemoryStoreActor::from(store.clone()).start())
                    .with_interval(std::time::Duration::from_secs(60))
                    .with_max_requests(120),
            )
            .wrap(Logger::default())
            .service(
                web::scope("/notes")
                    .route("/new", web::post().to(handlers::note::new))
                    .route("/get/{id}", web::post().to(handlers::note::get))
                    .service(
                        web::scope("/plain")
                            .route("", web::post().to(handlers::plain_note::new))
                            .route("/{id}", web::get().to(handlers::plain_note::get)),
                    ),
            )
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}

#[derive(Debug)]
pub enum ServerError {
    ArgonError,
    DieselError,
    EnvironmentError,
    R2D2Error,
    MagicCryptError,
    InvalidCred,
    UserError(&'static str),
    NotFound(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Test")
    }
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
            ServerError::UserError(msg) => {
                HttpResponse::BadRequest().json(format!("Invalid Request: {}", msg.to_string()))
            }
            ServerError::NotFound(id) => HttpResponse::NotFound()
                .json(format!("Content with the id of: '{}' was not found", id)),
        }
    }
}
