use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305};
use ring::digest;
use sha1::{Digest, Sha1};

fn main() {
    let shared_secret = std::env::var("SHARED_SECRET")
        .unwrap_or_else(|_| "01234567012345670123456701234567".to_string());
    let _ = Sha1::digest(shared_secret.as_bytes());
    let _ = ChaCha20Poly1305::new_from_slice(&shared_secret.as_bytes()[..32]);
    let _ = digest::SHA256_OUTPUT_LEN;
    println!("{}", shared_secret.len());
}
