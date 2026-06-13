use sha2::{Digest, Sha256};

fn main() {
    let secret = std::env::var("SECRET").unwrap_or_else(|_| "default".to_string());
    let bytes = secret.as_bytes();
    let digest1 = Sha256::digest(bytes);

    let trimmed = secret.trim().to_lowercase();
    let digest2 = Sha256::digest(trimmed.as_bytes());

    let owned = secret.to_owned();
    let _digest3 = Sha256::digest(owned.as_bytes());

    let _ = digest1;
    let _ = digest2;
}
