use ed25519_dalek::SigningKey;
use rand::thread_rng;
use ring::aead::{AES_256_GCM, UnboundKey};
use ring::digest::{digest, SHA256};
use rsa::RsaPrivateKey;

fn main() {
    let signing_secret = std::env::var("SIGNING_SECRET")
        .unwrap_or_else(|_| "01234567012345670123456701234567".to_string());

    let _ = digest(&SHA256, signing_secret.as_bytes());
    let _ = UnboundKey::new(&AES_256_GCM, &signing_secret.as_bytes()[..32]);

    let mut rng = thread_rng();
    let _ = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let _ = SigningKey::from_bytes(&[42u8; 32]);

    println!("{}", signing_secret.len());
}
