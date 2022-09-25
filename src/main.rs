use std::time::SystemTime;

use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{middleware::Logger, web, App, HttpServer};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use jsonwebtoken::{Algorithm, Header, Validation};

#[macro_use]
extern crate diesel;

mod errors;
mod handlers;
mod schema;

const MIGRATION: EmbeddedMigrations = embed_migrations!();

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let env = AppState::init();
    let address = env.app_address.to_owned();
    let pool = r2d2::Pool::builder()
        .build(ConnectionManager::<PgConnection>::new(
            env.db_url.to_owned(),
        ))
        .expect("Failed to create a pool");

    let mut connection = pool.get().unwrap();
    MigrationHarness::run_pending_migrations(&mut pool.get().unwrap(), MIGRATION)
        .expect("migration run failed, please check your database configuration!");
    std::thread::spawn(move || loop {
        use schema::notes::dsl::notes;
        log::info!("Clearing expired notes from database!");
        diesel::delete(notes.filter(schema::notes::expires_at.le(SystemTime::now())))
            .execute(&mut connection)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(env.cleanup_interval));
    });

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(env.clone()))
            .app_data(web::Data::new(pool.clone()))
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
            // paths should be defined per handlers
            // https://actix.rs/actix-web/actix_web/struct.App.html#method.configure
            .service(
                web::scope("/notes")
                    .service(handlers::note::mutate::new)
                    .service(handlers::note::query::info)
                    .service(handlers::note::query::search_by_title)
                    .service(handlers::note::query::decrypt_note)
                    .service(handlers::note::mutate::del),
            )
            .service(
                web::scope("/token")
                    .service(handlers::token::verify)
                    .service(handlers::token::combine)
                    .service(handlers::token::refresh_token),
            )
    })
    .bind(address)?
    .run()
    .await
}

#[derive(Clone)]
pub struct AppState {
    pub secret: String,
    pub jwt_validator: Validation,
    pub jwt_header: Header,
    db_url: String,
    app_address: String,
    cleanup_interval: u64,
}

impl AppState {
    fn init() -> Self {
        dotenv::dotenv().ok();
        env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

        let mut validation = Validation::new(Algorithm::HS512);
        validation.required_spec_claims = std::collections::HashSet::new();
        validation.validate_exp = false;

        Self {
            cleanup_interval: std::env::var("CLEANUP_INTERVAL")
                .unwrap_or("2700".to_string())
                .parse::<u64>()
                .expect("must be an unsigned 64-bit number"),
            jwt_validator: validation,
            jwt_header: Header::new(Algorithm::HS512),
            secret: std::env::var("SECRET_KEY").expect("SECRET_KEY in .env"),
            db_url: std::env::var("DATABASE_URL").expect("DATABASE_URL in .env"),
            app_address: format!(
                "0.0.0.0:{}",
                std::env::var("PORT").unwrap_or("8080".to_string())
            ),
        }
    }
}
