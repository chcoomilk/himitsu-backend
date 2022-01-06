use actix_web::HttpRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub fn get_token(req: HttpRequest) -> Option<String> {
    if let Some(auth) = req.headers().get("authorization") {
        let vec: Vec<&str> = auth.to_str().unwrap().split_whitespace().collect();
        Some(vec[1].to_string())
    } else {
        None
    }
}
