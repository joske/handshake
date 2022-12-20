use std::error::Error;

use aead::{AeadMut, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::cipher::Cipher;

#[derive(Default)]
pub struct CipherAesGcm {
    cipher: Option<Aes256Gcm>,
}

impl Cipher for CipherAesGcm {
    fn cipher_key_len(&self) -> usize {
        32
    }

    /// initialize the cipher with a key
    /// We need to have the cipher key length before we have the key
    fn set_key(&mut self, key: &[u8]) {
        self.cipher = Some(Aes256Gcm::new(key.into()));
    }

    fn encrypt_ad(
        &mut self,
        nonce: u64,
        ad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        if self.cipher.is_none() {
            return Err("Cipher not initialized".into());
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let p = Payload {
            msg: plaintext,
            aad: ad,
        };
        let ciphertext = self
            .cipher
            .as_mut()
            .unwrap() // this unwrap is fine as we've already checked the precondition above
            .encrypt(nonce, p)
            .map_err(|_| Box::<dyn Error>::from("encrypt"))?;
        let len = ciphertext.len();
        out[..len].copy_from_slice(ciphertext.as_slice());
        Ok(len)
    }

    fn decrypt_ad(
        &mut self,
        nonce: u64,
        ad: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        if self.cipher.is_none() {
            return Err("Cipher not initialized".into());
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let p = Payload { msg: data, aad: ad };
        let plaintext = self
            .cipher
            .as_mut()
            .unwrap() // this unwrap is fine as we've already checked the precondition above
            .decrypt(nonce, p)
            .map_err(|_| Box::<dyn Error>::from("decrypt"))?;
        let len = plaintext.len();
        out[..len].copy_from_slice(&plaintext);
        Ok(len)
    }
}
