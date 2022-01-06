pub mod note;

pub async fn index() -> impl actix_web::Responder {
    actix_web::HttpResponse::Ok().body("Hello")
}
