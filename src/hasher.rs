use blake2::{Blake2b, Blake2b512, Blake2s, Blake2s256, Digest};
use sha2::{Sha256, Sha512};
use std::{error::Error, str::FromStr};
use strum::EnumString;

pub const MAX_HASH_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
pub enum Hashers {
    SHA256,
    SHA512,
    BLAKE2s,
    BLAKE2b,
}
pub trait Hasher: Send + Sync {
    fn hash_len(&self) -> usize;
    fn block_len(&self) -> usize;
    fn reset(&mut self);
    fn update(&mut self, data: &[u8]);
    fn output(&mut self, out: &mut [u8]);
}

/// Construct a `Hasher` from the handshake name
///
/// # Errors
///
/// Will return `Err` if a an algorithm other than BLAKE2s or SHA256 is requested
pub fn from_handshake_name(name: &str) -> Result<Box<dyn Hasher>, Box<dyn Error>> {
    let mut bits = name.split('_');
    if let Some(h) = bits.nth(4) {
        let from_str = Hashers::from_str(h);
        if let Ok(h) = from_str {
            match h {
                Hashers::BLAKE2s => Ok(Box::<HasherBlake2s>::default()),
                Hashers::BLAKE2b => Ok(Box::<HasherBlake2b>::default()),
                Hashers::SHA256 => Ok(Box::<HasherSha256>::default()),
                Hashers::SHA512 => Ok(Box::<HasherSha512>::default()),
            }
        } else {
            Err("Failed to parse hasher algorithm".into())
        }
    } else {
        Err("Failed to parse hasher algorithm".into())
    }
}

#[derive(Default)]
pub struct HasherBlake2s {
    hasher: Blake2s256,
}

impl HasherBlake2s {
    #[must_use]
    pub fn new() -> Self {
        Self { hasher: Blake2s::default() }
    }
}

impl Hasher for HasherBlake2s {
    fn hash_len(&self) -> usize {
        32usize
    }

    fn block_len(&self) -> usize {
        64usize
    }

    fn reset(&mut self) {
        self.hasher = Blake2s::default();
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn output(&mut self, out: &mut [u8]) {
        let output = self.hasher.finalize_reset();
        let len = self.hash_len();
        out[..len].copy_from_slice(output.as_slice());
    }
}

#[derive(Default)]
pub struct HasherBlake2b {
    hasher: Blake2b512,
}

impl HasherBlake2b {
    #[must_use]
    pub fn new() -> Self {
        Self { hasher: Blake2b::default() }
    }
}

impl Hasher for HasherBlake2b {
    fn hash_len(&self) -> usize {
        64usize
    }

    fn block_len(&self) -> usize {
        128usize
    }

    fn reset(&mut self) {
        self.hasher = Blake2b::default();
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn output(&mut self, out: &mut [u8]) {
        let output = self.hasher.finalize_reset();
        let len = self.hash_len();
        out[..len].copy_from_slice(output.as_slice());
    }
}

#[derive(Default)]
struct HasherSha256 {
    hasher: Sha256,
}

impl Hasher for HasherSha256 {
    fn hash_len(&self) -> usize {
        32
    }

    fn block_len(&self) -> usize {
        64usize
    }

    fn reset(&mut self) {
        self.hasher = Sha256::new();
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn output(&mut self, out: &mut [u8]) {
        let result = self.hasher.finalize_reset();
        out[..result.len()].copy_from_slice(result.as_slice());
    }
}

#[derive(Default)]
struct HasherSha512 {
    hasher: Sha512,
}

impl Hasher for HasherSha512 {
    fn hash_len(&self) -> usize {
        64
    }

    fn block_len(&self) -> usize {
        128usize
    }

    fn reset(&mut self) {
        self.hasher = Sha512::new();
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn output(&mut self, out: &mut [u8]) {
        let result = self.hasher.finalize_reset();
        out[..result.len()].copy_from_slice(result.as_slice());
    }
}

#[cfg(test)]
mod tests {
    use crate::hasher::from_handshake_name;

    #[test]
    fn test_hasher_empty() {
        let hasher = from_handshake_name("");
        assert!(hasher.is_err());
    }

    #[test]
    fn test_hasher_sha256() {
        let hasher = from_handshake_name("Noise_XXpsk3_25519_ChaChaPoly_SHA256");
        assert!(hasher.is_ok());
        let mut hasher = hasher.unwrap();
        let mut out = [0u8; 32];
        hasher.update("rust rules".as_bytes());
        hasher.update("for sure".as_bytes());
        hasher.output(&mut out);
        let h = hex::encode(out);
        assert_eq!("317fce3c1139697d19645d29eaf305a62c88043ad8b8ace56141364fcd97d00d", h);
    }

    #[test]
    fn test_hasher_sha512() {
        let hasher = from_handshake_name("Noise_XXpsk3_25519_ChaChaPoly_SHA512");
        assert!(hasher.is_ok());
        let mut hasher = hasher.unwrap();
        let mut out = [0u8; 64];
        hasher.update("rust rules".as_bytes());
        hasher.update("for sure".as_bytes());
        hasher.output(&mut out);
        let h = hex::encode(out);
        assert_eq!(
            "fb6671340955f6dd734d508f47e4618a3a07b85e0d960c66ddf8f26dd682b518622c2418d1885d9a4c572be8a73ad4088d20d16d9bd5dc8594920c388c911b3c",
            h
        );
    }

    #[test]
    fn test_hasher_blake2b() {
        let hasher = from_handshake_name("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b");
        assert!(hasher.is_ok());
        let mut hasher = hasher.unwrap();
        let mut out = [0u8; 64];
        hasher.update("rust rules".as_bytes());
        hasher.update("for sure".as_bytes());
        hasher.output(&mut out);
        let h = hex::encode(out);
        assert_eq!(
            "608161eca5537efb40d538eef54c57e471e17230a42d1f68bcbd0ae3ade2f5a608bcd463d7f89ba1bb95b04fe1f85bcbdb5559508b2797b45814b88130412e4f",
            h
        );
    }

    #[test]
    fn test_hasher_blake2s() {
        let hasher = from_handshake_name("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s");
        assert!(hasher.is_ok());
        let mut hasher = hasher.unwrap();
        let mut out = [0u8; 32];
        hasher.update("rust rules".as_bytes());
        hasher.output(&mut out);
        let h = hex::encode(out);
        assert_eq!("6ad446d3fc8e3ef1f81a189f08c4794ac7b6b4dd211c47e456c5c1119e7ce95c", h);
    }
}
