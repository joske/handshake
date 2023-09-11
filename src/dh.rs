use rand_core::{OsRng, RngCore};
use std::{error::Error, str::FromStr};
use strum::EnumString;
use x25519_dalek::x25519;
use x448::x448_unchecked;

pub const MAX_DH_LEN: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
pub enum DHs {
    #[strum(serialize = "25519")]
    D25519,
    #[strum(serialize = "448")]
    D448,
}

pub trait DH {
    fn dh_len(&self) -> usize;
    fn private(&self) -> &[u8];
    fn public(&self) -> &[u8];
    fn dh(&self, public: &[u8], out: &mut [u8]);

    /// generate a random private key and derive the matching public key
    fn generate(&mut self);
}

/// Construct a `DH` from the handshake name
///
/// # Errors
///
/// Will return `Err` if a an algorithm could not be parsed
pub fn from_handshake_name(name: &str) -> Result<Box<dyn DH>, Box<dyn Error>> {
    let mut bits = name.split('_');
    if let Some(h) = bits.nth(2) {
        let from_str = DHs::from_str(h);
        if let Ok(h) = from_str {
            match h {
                DHs::D25519 => Ok(Box::<DH25519>::default()),
                DHs::D448 => Ok(Box::<DH448>::default()),
            }
        } else {
            Err("Failed to parse DH algorithm".into())
        }
    } else {
        Err("Failed to parse DH algorithm".into())
    }
}

#[derive(Default)]
pub struct DH25519 {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl DH for DH25519 {
    fn dh_len(&self) -> usize {
        32
    }

    fn dh(&self, public: &[u8], out: &mut [u8]) {
        let mut p = [0u8; 32];
        p.copy_from_slice(&public[..32]);
        let dh = x25519_dalek::x25519(self.private, p);
        out[..32].copy_from_slice(&dh);
    }

    fn generate(&mut self) {
        OsRng.fill_bytes(&mut self.private);
        self.public = x25519(self.private, x25519_dalek::X25519_BASEPOINT_BYTES);
    }

    fn private(&self) -> &[u8] {
        &self.private
    }

    fn public(&self) -> &[u8] {
        &self.public
    }
}

pub struct DH448 {
    pub private: [u8; 56],
    pub public: [u8; 56],
}

impl Default for DH448 {
    fn default() -> Self {
        Self {
            private: [0u8; 56],
            public: [0u8; 56],
        }
    }
}

impl DH for DH448 {
    fn dh_len(&self) -> usize {
        56
    }

    fn dh(&self, public: &[u8], out: &mut [u8]) {
        let mut p = [0u8; 56];
        p.copy_from_slice(&public[..56]);
        let dh = x448_unchecked(self.private, p);
        out[..56].copy_from_slice(&dh);
    }

    fn generate(&mut self) {
        OsRng.fill_bytes(&mut self.private);
        self.public = x448::x448_unchecked(self.private, x448::X448_BASEPOINT_BYTES);
    }

    fn private(&self) -> &[u8] {
        &self.private
    }

    fn public(&self) -> &[u8] {
        &self.public
    }
}

#[cfg(test)]
mod test {
    use crate::dh::{from_handshake_name, DH448};

    use super::{DH, DH25519};

    #[test]
    fn test_empty() {
        let dh = from_handshake_name("");
        assert!(dh.is_err());
    }

    #[test]
    fn test_invalid() {
        let dh = from_handshake_name("Noise_XXpsk3_1234_ChaChaPoly_BLAKE2s");
        assert!(dh.is_err());
    }

    #[test]
    fn test_from_25519() {
        let hasher = from_handshake_name("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s");
        assert!(hasher.is_ok());
    }

    #[test]
    fn test_25519() {
        let e = [1u8; 32];
        let dh = DH25519 {
            private: e,
            public: e,
        };
        let re = [2u8; 32];
        let mut out = [0u8; 32];
        dh.dh(&re, &mut out);
        assert_eq!(
            "047f039121185037c302191e45982949f7d9b2c310cf0e173321535fbc14df3e",
            hex::encode(out)
        );
    }

    #[test]
    fn test_448() {
        let e = [1u8; 56];
        let dh = DH448 {
            private: e,
            public: e,
        };
        let re = [2u8; 56];
        let mut out = [0u8; 56];
        dh.dh(&re, &mut out);
        assert_eq!(
            "6d18773e3ad798d5a84c593883c5041cc925fcf1857a21f7fedff276469ffbe71c4db1604e5c1c607866192ee8d6c6a233bafa38337e0330",
            hex::encode(out)
        );
    }
}
