use std::error::Error;
use std::str::FromStr;
use strum::EnumString;

use crate::aes::CipherAesGcm;
use crate::chacha::CipherChaCha;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
pub enum Ciphers {
    AESGCM,
    ChaChaPoly,
}

/// Construct a `Cipher` from the handshake name
///
/// # Errors
///
/// Will return `Err` if a an algorithm other than `ChaChaPoly` is required
pub fn from_handshake_name(name: &str) -> Result<Box<dyn Cipher>, Box<dyn Error>> {
    let mut bits = name.split('_');
    if let Some(h) = bits.nth(3) {
        let from_str = Ciphers::from_str(h);
        if let Ok(h) = from_str {
            match h {
                Ciphers::ChaChaPoly => Ok(Box::<CipherChaCha>::default()),
                Ciphers::AESGCM => Ok(Box::<CipherAesGcm>::default()),
            }
        } else {
            Err("Failed to parse cipher algorithm".into())
        }
    } else {
        Err("Failed to parse cipher algorithm".into())
    }
}

pub trait Cipher {
    fn cipher_key_len(&self) -> usize;
    fn set_key(&mut self, key: &[u8]);

    /// encrypt the ciphertext given with the given AD in `ad`
    /// output in pre-allocated buffer `out`
    ///
    /// # Errors
    ///
    /// Returns `Err` if cipher not initialized
    fn encrypt_ad(
        &mut self,
        nonce: u64,
        ad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>>;

    /// decrypt the ciphertext given with the given AD in `ad`
    /// output in pre-allocated buffer `out`
    ///
    /// # Errors
    ///
    /// Returns `Err` if cipher not initialized
    fn decrypt_ad(
        &mut self,
        nonce: u64,
        ad: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>>;
}

pub struct CipherState {
    n: u64,
    cipher: Box<dyn Cipher>,
    has_key: bool,
}

impl CipherState {
    /// Construct a `CipherState` object.
    ///
    /// # Errors
    ///
    /// Will return `Err` if a an algorithm other than `ChaChaPoly` is requested
    pub fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        let cipher = from_handshake_name(name)?;
        Ok(Self {
            n: 0,
            cipher,
            has_key: false,
        })
    }

    pub fn init(&mut self, key: &[u8], n: u64) {
        self.n = n;
        self.has_key = true;
        self.cipher.as_mut().set_key(key);
    }

    #[must_use]
    pub fn key_len(&self) -> usize {
        self.cipher.as_ref().cipher_key_len()
    }

    /// encrypt the ciphertext given with the given AD in `ad`
    /// output in pre-allocated buffer `out`
    ///
    /// # Errors
    ///
    /// Returns `Err` if cipher not initialized
    pub fn encrypt(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        let len = self
            .cipher
            .as_mut()
            .encrypt_ad(self.n, ad, plaintext, out)?;
        self.n += 1; // we'll not worry about overflow here, 64 bits should be enough for one handshake ;-)
        Ok(len)
    }

    /// decrypt the ciphertext given with the given AD in `ad`
    /// output in pre-allocated buffer `out`
    ///
    /// # Errors
    ///
    /// Returns `Err` if cipher not initialized
    pub fn decrypt(
        &mut self,
        ad: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        let len = self.cipher.as_mut().decrypt_ad(self.n, ad, data, out)?;
        self.n += 1; // we'll not worry about overflow here, 64 bits should be enough for one handshake ;-)
        Ok(len)
    }

    // no need for rekey() in this example
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_bad_handshake_name() {
        let cipher_state = crate::cipher::CipherState::new("");
        assert!(cipher_state.is_err());
    }

    #[test]
    fn test_encrypt_should_fail_if_no_key_set() {
        let mut cipher_state =
            crate::cipher::CipherState::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s").unwrap();
        let plaintext = [3u8; 64];
        let authtext = [2u8; 32];
        let mut out = [0u8; 128];
        let result = cipher_state.encrypt(&authtext, &plaintext, &mut out);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_should_fail_if_no_key_set() {
        let mut cipher_state =
            crate::cipher::CipherState::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s").unwrap();
        let plaintext = [3u8; 64];
        let authtext = [2u8; 32];
        let mut out = [0u8; 128];
        let result = cipher_state.decrypt(&authtext, &plaintext, &mut out);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt() {
        let mut cipher_state =
            crate::cipher::CipherState::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s").unwrap();
        let key = [1u8; 32];
        cipher_state.init(&key, 0);
        let plaintext = [3u8; 64];
        let authtext = [2u8; 32];
        let mut out = [0u8; 128];
        let len = cipher_state
            .encrypt(&authtext, &plaintext, &mut out)
            .unwrap();
        let hex = hex::encode(&out[..len]);
        assert_eq!("02244ed2ed5115c107f86a8eada75851ea886c0cde076ecf3985b8049d35f327177d48845e5aaaec40288d46b3499bc7b29ecbc4445c5ecd415ab7c92ed57181affbc69d77d72e11d832d21ce3df33c6", hex);
    }

    #[test]
    fn test_decrypt() {
        let mut cipher_state =
            crate::cipher::CipherState::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s").unwrap();
        let key = [1u8; 32];
        cipher_state.init(&key, 0);
        let ciphertext = hex::decode("02244ed2ed5115c107f86a8eada75851ea886c0cde076ecf3985b8049d35f327177d48845e5aaaec40288d46b3499bc7b29ecbc4445c5ecd415ab7c92ed57181affbc69d77d72e11d832d21ce3df33c6").unwrap();
        let plaintext = [3u8; 64];
        let authtext = [2u8; 32];
        let mut out = [0u8; 128];
        let len = cipher_state
            .decrypt(&authtext, &ciphertext, &mut out)
            .unwrap();
        assert_eq!(plaintext, out[..len]);
    }

    #[test]
    fn test_encrypt_aes() {
        let mut cipher_state =
            crate::cipher::CipherState::new("Noise_XXpsk3_25519_AESGCM_BLAKE2s").unwrap();
        let key = [1u8; 32];
        cipher_state.init(&key, 0);
        let plaintext = [3u8; 64];
        let authtext = [2u8; 32];
        let mut out = [0u8; 128];
        let len = cipher_state
            .encrypt(&authtext, &plaintext, &mut out)
            .unwrap();
        let hex = hex::encode(&out[..len]);
        assert_eq!("bc369bdf763800bc907a91467227c242b6c59cb3869c37f9cf270dd60dd56d185dbbaef850edbc6b2495d479e3b5a0edada5ae9fc8d49757cc001fbc1ce9998c241d11e43ea285df6aec4938762759c4", hex);
    }
}
