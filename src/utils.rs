use actix_web::{HttpRequest};
// use argon2::{Version, PasswordVerifier, PasswordHash, Argon2, Algorithm, Params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub fn _get_token(req: HttpRequest) -> Option<String> {
    if let Some(auth) = req.headers().get("authorization") {
        let vec: Vec<&str> = auth.to_str().unwrap().split_whitespace().collect();
        Some(vec[1].to_string())
    } else {
        None
    }
}

// pub fn _is_password_valid(hash: &String, input: &String) -> Result<bool, ServerError> {
//     let secret = std::env::var("SECRET_KEY")?;
//     let parsed_hash = PasswordHash::new(&hash)?;
//     let valid = Argon2::new_with_secret(
//         secret.as_bytes(),
//         Algorithm::default(),
//         Version::default(),
//         Params::default(),
//     )?
//     .verify_password(&input.as_bytes(), &parsed_hash)
//     .is_ok();
//     Ok(valid)
// }
