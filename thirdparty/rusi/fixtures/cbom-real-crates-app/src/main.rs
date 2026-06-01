use aes_gcm::{aead::KeyInit, Aes256Gcm};
use argon2::{password_hash::{PasswordHasher, SaltString}, Argon2};
use hmac::Hmac;
use jsonwebtoken::EncodingKey;
use pbkdf2::pbkdf2_hmac;
use rustls::ClientConfig;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct Claims {
    sub: String,
}

fn main() {
    let app_secret = std::env::var("APP_SECRET")
        .unwrap_or_else(|_| "01234567012345670123456701234567".to_string());
    let api_token = app_secret.clone();
    let _claims = Claims {
        sub: "alice".to_string(),
    };

    let _ = Sha256::digest(app_secret.as_bytes());
    let _ = md5::compute(app_secret.as_bytes());
    let _ = blake3::hash(app_secret.as_bytes());
    let _ = Aes256Gcm::new_from_slice(&app_secret.as_bytes()[..32]);
    let _ = Hmac::<Sha256>::new_from_slice(app_secret.as_bytes());

    let app_key = EncodingKey::from_secret(app_secret.as_bytes());
    let _ = app_key;

    let mut nonce_seed = [0u8; 32];
    pbkdf2_hmac::<Sha256>(app_secret.as_bytes(), b"saltysalt", 1_000, &mut nonce_seed);

    let app_salt = SaltString::encode_b64(b"fixed-salt-value").unwrap();
    let _ = Argon2::default().hash_password(app_secret.as_bytes(), &app_salt);

    let _ = ClientConfig::builder();
    println!("{}{}", api_token.len(), nonce_seed[0]);
}
