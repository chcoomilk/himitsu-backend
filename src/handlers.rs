pub mod note;
pub mod plain_note;

pub async fn index() -> impl actix_web::Responder {
  actix_web::HttpResponse::Ok().body("Hello")
}
