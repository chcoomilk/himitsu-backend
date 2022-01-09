use std::time::SystemTime;

use actix_cors::Cors;
use actix_ratelimit::{MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::{middleware::Logger, web, App, HttpServer};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;

#[macro_use]
extern crate diesel;

mod errors;
mod handlers;
mod models;
mod schema;
mod utils;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    std::env::var("SECRET_KEY").expect("SECRET_KEY in .env");

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let pool = r2d2::Pool::builder()
        .build(ConnectionManager::<PgConnection>::new(
            std::env::var("DATABASE_URL").expect("DATABASE_URL in .env"),
        ))
        .expect("fail to create a pg pool");

    let interval = std::env::var("CLEANUP_INTERVAL")
        .unwrap_or("2700".to_string())
        .parse::<u64>()
        .expect("CLEANUP_INTERVAL must be postive integer");
    let connection = pool.get().unwrap();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        use schema::notes::dsl::notes;
        diesel::delete(notes.filter(schema::notes::expired_at.le(SystemTime::now())))
            .execute(&connection)
            .unwrap();
    });

    let port = std::env::var("PORT").unwrap_or("8080".to_string());
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
                RateLimiter::new(MemoryStoreActor::from(MemoryStore::new().clone()).start())
                    .with_interval(std::time::Duration::from_secs(60))
                    .with_max_requests(120),
            )
            .wrap(Logger::default())
            .service(
                web::scope("/notes")
                    .route("/new/", web::post().to(handlers::note::new))
                    .route("/{id}", web::delete().to(handlers::note::del))
                    .route("/{id}", web::get().to(handlers::note::get_info))
                    .route("/{id}", web::post().to(handlers::note::decrypt)),
            )
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}
