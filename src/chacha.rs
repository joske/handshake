use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::error::Error;

use crate::cipher::Cipher;

#[derive(Default)]
pub struct CipherChaCha {
    cipher: Option<ChaCha20Poly1305>,
}

impl Cipher for CipherChaCha {
    fn cipher_key_len(&self) -> usize {
        32
    }

    /// initialize the cipher with a key
    /// We need to have the cipher key length before we have the key
    fn set_key(&mut self, key: &[u8]) {
        let ck = Key::from_slice(key);
        self.cipher = Some(ChaCha20Poly1305::new(ck));
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
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
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
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
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
