use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

mod sha2 {
    pub trait Digest {
        fn digest(data: &[u8]) -> Vec<u8>;
    }

    pub struct Sha256;

    impl Digest for Sha256 {
        fn digest(data: &[u8]) -> Vec<u8> {
            let mut out = vec![0u8; 32];
            for (index, byte) in data.iter().enumerate() {
                out[index % 32] ^= *byte;
            }
            out
        }
    }
}

mod aes_gcm {
    pub mod aead {
        pub trait KeyInit: Sized {
            fn new_from_slice(key: &str) -> Result<Self, &'static str>;
        }
    }

    pub struct Aes256Gcm(Vec<u8>);

    impl aead::KeyInit for Aes256Gcm {
        fn new_from_slice(key: &str) -> Result<Self, &'static str> {
            if key.is_empty() {
                Err("empty key")
            } else {
                Ok(Self(key.as_bytes().to_vec()))
            }
        }
    }

    impl Aes256Gcm {
        pub fn key_len(&self) -> usize {
            self.0.len()
        }
    }
}

use aes_gcm::Aes256Gcm;
use sha2::{Digest, Sha256};

fn noop_raw_waker() -> RawWaker {
    fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    fn wake(_: *const ()) {}
    fn wake_by_ref(_: *const ()) {}
    fn drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    RawWaker::new(std::ptr::null(), &VTABLE)
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match Pin::new(&mut future).poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

async fn load_key() -> String {
    std::env::var("APP_KEY").unwrap_or_else(|_| "01234567012345670123456701234567".to_string())
}

async fn encryptor(key_material: String) -> usize {
    let producer = || key_material.clone();
    let captured_key = producer();
    let _digest = Sha256::digest(captured_key.as_bytes());
    let cipher = <Aes256Gcm as aes_gcm::aead::KeyInit>::new_from_slice(&captured_key)
        .expect("cipher init");

    let spawned = std::thread::spawn(move || captured_key.len());
    let _ = spawned.join();

    cipher.key_len()
}

fn main() {
    let direct_key = std::env::var("APP_KEY").expect("key from environment");
    let _direct_cipher = <Aes256Gcm as aes_gcm::aead::KeyInit>::new_from_slice(&direct_key)
        .expect("direct cipher init");
    let key = block_on(load_key());
    let _ = block_on(encryptor(key));
}
