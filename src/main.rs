use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::SystemTime;

use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{middleware::Logger, web, App, HttpServer};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;

#[macro_use]
extern crate diesel;

// use crate::diesel;

mod errors;
mod handlers;
mod models;
mod schema;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let env = Envar::init();
    let address = env.app_address.to_owned();
    let pool = r2d2::Pool::builder()
        .build(ConnectionManager::<PgConnection>::new(
            env.db_url.to_owned(),
        ))
        .expect("Failed to create a pool");

    let connection = pool.get().unwrap();
    std::thread::spawn(move || loop {
        use schema::notes::dsl::notes;
        diesel::delete(notes.filter(schema::notes::expires_at.le(SystemTime::now())))
            .execute(&connection)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(env.cleanup_interval));
    });

    let app_state = Arc::new(AtomicUsize::new(0));

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(env.clone()))
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(app_state.clone()))
            .route("/", web::get().to(handlers::index))
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
                    .max_age(3600),
            )
            .wrap(Governor::new(
                &GovernorConfigBuilder::default()
                    .per_millisecond(1500)
                    .burst_size(3)
                    .finish()
                    .unwrap(),
            ))
            .wrap(Logger::default())
            .service(
                web::scope("/notes")
                .service(handlers::note::post::new)
                    // .route("", web::post().to(handlers::note::new))
                    .route("", web::get().to(handlers::note::search_by_title))
                    .route("/{id}", web::delete().to(handlers::note::del))
                    .route("/{id}", web::get().to(handlers::note::get_info))
                    .route("/{id}", web::post().to(handlers::note::decrypt)),
            )
    })
    .bind(address)?
    .run()
    .await
}

#[derive(Clone)]
pub struct Envar {
    pub secret: String,
    db_url: String,
    app_address: String,
    cleanup_interval: u64,
}

impl Envar {
    fn init() -> Self {
        dotenv::dotenv().ok();
        env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

        Self {
            cleanup_interval: std::env::var("CLEANUP_INTERVAL")
                .unwrap_or("2700".to_string())
                .parse::<u64>()
                .expect("must be an unsigned 64-bit number"),
            secret: std::env::var("SECRET_KEY").expect("SECRET_KEY in .env"),
            db_url: std::env::var("DATABASE_URL").expect("DATABASE_URL in .env"),
            app_address: format!(
                "0.0.0.0:{}",
                std::env::var("PORT").unwrap_or("8080".to_string())
            ),
        }
    }
}
