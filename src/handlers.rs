use diesel::{pg::PgConnection, r2d2::ConnectionManager};

pub mod note;
pub mod token;
pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub async fn index() -> impl actix_web::Responder {
    actix_web::HttpResponse::Ok().finish()
}
