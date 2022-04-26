use std::sync::atomic::{AtomicUsize, Ordering};

use actix_web::web;
use diesel::{pg::PgConnection, r2d2::ConnectionManager};
use tindercrypt::cryptors::RingCryptor;

pub mod note;
pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub async fn index(note_count: web::Data<AtomicUsize>) -> impl actix_web::Responder {
    let plaintext = "The cake is a lie".as_bytes();
    let pass = "My secret passphrase".as_bytes();
    let cryptor = RingCryptor::new();
    println!("Count: {}", note_count.load(Ordering::Relaxed));
    note_count.fetch_add(1, Ordering::SeqCst);
    let ciphertext = cryptor.seal_with_passphrase(pass, plaintext).unwrap();
    let plaintext2 = cryptor
        .open("My secret passphrase".as_bytes(), &ciphertext)
        .unwrap();
    actix_web::HttpResponse::Ok().body(format!("{}", std::str::from_utf8(&plaintext2).unwrap()))
}
