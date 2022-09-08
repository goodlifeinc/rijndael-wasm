// Credits to: https://github.com/tinternet
// for the kind support and help regarding Rust best practices.

mod utils;

use base64::decode;
use simple_rijndael::impls::RijndaelCbc;
use simple_rijndael::paddings::ZeroPadding;
use std::str;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct Error {
    message: String,
}

#[wasm_bindgen]
impl Error {
    pub fn message(self) -> String {
        self.message
    }
}

impl From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Self {
        Self {
            message: format!("Base64 error: {:?}", error),
        }
    }
}

impl From<simple_rijndael::Errors> for Error {
    fn from(error: simple_rijndael::Errors) -> Self {
        Self {
            message: format!("Decrypt error: {:?}", error),
        }
    }
}

impl From<str::Utf8Error> for Error {
    fn from(error: str::Utf8Error) -> Self {
        Self {
            message: format!("UTF8 error: {:?}", error),
        }
    }
}

#[wasm_bindgen]
pub fn decrypt(
    key_base64: &str,
    iv_base64: &str,
    encrypted_base64: &str,
) -> Result<String, Error> {
    let key = decode(&key_base64)?;
    let iv = decode(&iv_base64)?;
    let encrypted = decode(&encrypted_base64)?;

    let crypt = RijndaelCbc::<ZeroPadding>::new(&key, 32)?;
    let decrypted = crypt.decrypt(&iv, encrypted)?;

    let result = str::from_utf8(&decrypted)?;
    Ok(result.to_string())
}
