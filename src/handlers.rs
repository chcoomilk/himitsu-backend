use actix_web::web;
use diesel::{pg::PgConnection, r2d2::ConnectionManager};

pub mod note;
pub mod token;
pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/notes")
            .service(
                web::resource("")
                    .route(web::get().to(note::query::search_by_title))
                    .route(web::post().to(note::mutate::new)),
            )
            .service(
                web::resource("/{note_id}")
                    .route(web::get().to(note::query::info))
                    .route(web::post().to(note::query::decrypt_note))
                    .route(web::delete().to(note::mutate::del)),
            ),
    )
    .service(
        web::scope("/token").service(
            web::resource("")
                .route(web::post().to(token::verify))
                .route(web::put().to(token::combine))
                .route(web::patch().to(token::refresh_token)),
        ),
    );
    // cfg.service(
    //     web::scope("/token").service(
    //         web::resource("")
    //             .route(web::post().to(token::verify))
    //             .route(web::put().to(token::combine))
    //             .route(web::patch().to(token::refresh_token)),
    //     ),
    // );
}

pub async fn index() -> impl actix_web::Responder {
    actix_web::HttpResponse::Ok().finish()
}
