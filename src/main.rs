use std::time::SystemTime;

use actix_cors::Cors;
use actix_ratelimit::{MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::{middleware::Logger, web, App, HttpServer};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[macro_use]
extern crate diesel;

mod errors;
mod handlers;
mod models;
mod schema;
mod utils;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    std::env::var("SECRET_KEY").expect("env SECRET_KEY");
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let port = std::env::var("PORT").unwrap_or("8080".to_string());
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
        println!("cleaning");
        diesel::delete(notes.filter(schema::notes::expired_at.le(SystemTime::now())))
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
                    .route("/{id}", web::delete().to(handlers::note::del))
                    .route("/{id}", web::get().to(handlers::note::get_info))
                    .route("/{id}/decrypt", web::post().to(handlers::note::get)),
            )
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}
