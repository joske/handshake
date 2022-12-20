use crate::cipher::CipherState;
use crate::hasher::Hasher;
use crate::hasher::{from_handshake_name, MAX_HASH_LEN};
use std::error::Error;

pub struct SymmetricState {
    h: [u8; MAX_HASH_LEN],
    ck: [u8; MAX_HASH_LEN],
    hasher: Box<dyn Hasher>,
    cipher_state: CipherState,
}

impl SymmetricState {
    /// Construct a `SymmetricState` object.
    /// Also constructs a `CipherState` object.
    ///
    /// # Errors
    ///
    /// Will return `Err` if constructing the `CipherState` fails
    pub fn new(handshake: &str) -> Result<Self, Box<dyn Error>> {
        let hasher = from_handshake_name(handshake)?;
        Ok(Self {
            h: [0; MAX_HASH_LEN],
            ck: [0; MAX_HASH_LEN],
            hasher,
            cipher_state: CipherState::new(handshake)?,
        })
    }

    pub fn init(&mut self, handshake: &str) {
        let hash_len = self.hasher.hash_len();
        let bytes = handshake.as_bytes();
        let mut hash = [0u8; MAX_HASH_LEN];
        if bytes.len() <= hash_len {
            let len = bytes.len();
            hash[..len].copy_from_slice(&bytes);

        } else {
            self.hasher.update(bytes);
            self.hasher.output(&mut hash);
        }
        self.h.copy_from_slice(&hash[..]);
        self.ck.copy_from_slice(&self.h[..]);
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.update(&self.h[..hash_len]);
        self.hasher.update(data);
        let mut hash = [0u8; MAX_HASH_LEN];
        self.hasher.output(&mut hash);
        self.h[..hash_len].copy_from_slice(&hash[..hash_len]);
    }

    pub fn mix_key(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let cipher_key_len = self.cipher_state.key_len();
        let mut output = ([0u8; MAX_HASH_LEN], [0u8; MAX_HASH_LEN]);
        let mut ck = [0u8; MAX_HASH_LEN];
        ck.copy_from_slice(&self.ck);
        self.hkdf(
            &ck[..hash_len],
            data,
            2,
            &mut output.0,
            &mut output.1,
            &mut [],
        );
        self.ck.copy_from_slice(&output.0);
        self.cipher_state.init(&output.1[..cipher_key_len], 0);
    }

    pub fn mix_key_and_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let cipher_key_len = self.cipher_state.key_len();
        let mut output = (
            [0u8; MAX_HASH_LEN],
            [0u8; MAX_HASH_LEN],
            [0u8; MAX_HASH_LEN],
        );
        let mut ck = [0u8; MAX_HASH_LEN];
        ck.copy_from_slice(&self.ck);
        self.hkdf(
            &ck[..hash_len],
            data,
            3,
            &mut output.0,
            &mut output.1,
            &mut output.2,
        );
        self.ck.copy_from_slice(&output.0);
        self.mix_hash(&output.1[..hash_len]);
        self.cipher_state.init(&output.2[..cipher_key_len], 0);
    }

    pub fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        const MAXBLOCKLEN: usize = 128;
        let block_len = self.hasher.block_len();
        let hash_len = self.hasher.hash_len();
        let mut inner_pad = [0x36u8; MAXBLOCKLEN];
        let mut outer_pad = [0x5cu8; MAXBLOCKLEN];
        for i in 0..key.len() {
            inner_pad[i] ^= key[i];
            outer_pad[i] ^= key[i];
        }
        self.hasher.reset();
        self.hasher.update(&inner_pad[..block_len]);
        self.hasher.update(data);
        let mut inner = [0u8; MAX_HASH_LEN];
        let mut hash = [0u8; MAX_HASH_LEN];
        self.hasher.output(&mut hash);
        inner[..hash_len].copy_from_slice(&hash[..hash_len]);

        self.hasher.reset();
        self.hasher.update(&outer_pad[..block_len]);
        self.hasher.update(&inner[..hash_len]);
        let mut hash = [0u8; MAX_HASH_LEN];
        self.hasher.output(&mut hash);
        out[..hash_len].copy_from_slice(&hash[..hash_len]);
    }

    pub fn hkdf(
        &mut self,
        chaining_key: &[u8],
        input_key_material: &[u8],
        num_outputs: usize,
        out1: &mut [u8],
        out2: &mut [u8],
        out3: &mut [u8],
    ) {
        let hash_len = self.hasher.hash_len();
        let mut tmp = [0u8; MAX_HASH_LEN];
        self.hmac(chaining_key, input_key_material, &mut tmp);
        self.hmac(&tmp, &[1u8], out1);
        if num_outputs == 1 {
            return;
        }
        let mut in2 = [0u8; MAX_HASH_LEN + 1];
        in2[..hash_len].copy_from_slice(&out1[..hash_len]);
        in2[hash_len] = 2; // append 0x02
        self.hmac(&tmp, &in2[..=hash_len], out2);
        if num_outputs == 2 {
            return;
        }
        let mut in3 = [0u8; MAX_HASH_LEN + 1];
        in3[..hash_len].copy_from_slice(&out2[..hash_len]);
        in3[hash_len] = 3; // append 0x03
        self.hmac(&tmp, &in3[..=hash_len], out3);
    }

    /// Encrypts the data given in `plaintext`
    /// Mixes the output in the hash
    ///
    /// # Errors
    ///
    /// Will return `Err` if encryption fails
    pub fn encrypt_and_mix_hash(
        &mut self,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        let hash_len = self.hasher.hash_len();
        let len = self
            .cipher_state
            .encrypt(&self.h[..hash_len], plaintext, out)?;
        self.mix_hash(&out[..len]);
        Ok(len)
    }

    /// Decrypts the data given in `data`
    /// Mixes the input in the hash
    ///
    /// # Errors
    ///
    /// Will return `Err` if decryption fails
    pub fn decrypt_and_mix_hash(
        &mut self,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        let hash_len = self.hasher.hash_len();
        let len = self.cipher_state.decrypt(&self.h[..hash_len], data, out)?;
        self.mix_hash(data);
        Ok(len)
    }

    pub fn split(&mut self, child1: &mut CipherState, child2: &mut CipherState) {
        let key_len = self.cipher_state.key_len();
        let mut out1 = [0u8; MAX_HASH_LEN];
        let mut out2 = [0u8; MAX_HASH_LEN];
        let mut ck = [0u8; MAX_HASH_LEN];
        ck.copy_from_slice(&self.ck);
        self.hkdf(&ck, &[0u8; 0], 2, &mut out1, &mut out2, &mut []);
        child1.init(&out1[..key_len], 0);
        child2.init(&out2[..key_len], 0);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mix_hash() {
        let mut hasher = SymmetricState::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s").unwrap();
        let len = hasher.hasher.hash_len();
        hasher.init("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s");
        hasher.mix_hash(&[]);
        assert_eq!(
            "20649ff124733a4f199402540c1dd40c0727738d478c3debc12892decd3d3f63",
            hex::encode(&hasher.h[..len])
        );
    }

    #[test]
    fn test_mix_key() {
        let mut hasher = SymmetricState::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s").unwrap();
        let len = hasher.hasher.hash_len();
        hasher.init("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s");
        let key = [1u8; 32];
        hasher.mix_key(&key);
        assert_eq!(
            "9c3d01c9c998993ff7791afe0f4ced62584f2c9c65d0b4f98d92b7dcb7b2ebed",
            hex::encode(&hasher.h[..len])
        );
        assert_eq!(
            "030316107e2ed6b10ca527eb01fceb367926f81b1b8b15d4a5db7ed2ba9f9a2b",
            hex::encode(&hasher.ck[..len])
        );
    }

    #[test]
    fn test_mix_key_and_hash() {
        let mut hasher = SymmetricState::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s").unwrap();
        let len = hasher.hasher.hash_len();
        hasher.init("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s");
        let key = [1u8; 32];
        hasher.mix_key_and_hash(&key);
        assert_eq!(
            "b914bba00d9f145ab192cef2689fff2d068a52cb5801242df4096916a49ca40d",
            hex::encode(&hasher.h[..len])
        );
        assert_eq!(
            "030316107e2ed6b10ca527eb01fceb367926f81b1b8b15d4a5db7ed2ba9f9a2b",
            hex::encode(&hasher.ck[..len])
        );
    }

    #[test]
    fn test_hmac() {
        let mut hasher = SymmetricState::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s").unwrap();
        let len = hasher.hasher.hash_len();
        let key = &[1u8; 64];
        let data = &[2u8; 64];
        let out = &mut [0u8; MAX_HASH_LEN];
        hasher.hmac(key, data, out);
        assert_eq!(
            "8883faf655b42a78605433682edbe455b6bcb6b8cccb80cebf7c9d05f8516670",
            hex::encode(&out[..len])
        );
    }

    #[test]
    fn test_hkdf() {
        let mut hasher = SymmetricState::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s").unwrap();
        let len = hasher.hasher.hash_len();
        let key = &[1u8; MAX_HASH_LEN];
        let data = &[2u8; MAX_HASH_LEN];
        let out1 = &mut [0u8; MAX_HASH_LEN];
        let out2 = &mut [0u8; MAX_HASH_LEN];
        let out3 = &mut [];
        hasher.hkdf(key, data, 2, out1, out2, out3);
        assert_eq!(
            "cbee9f4f3c70360368b251736d49fc8de6c5decae2b37967243e1f31cd344467",
            hex::encode(&out1[..len])
        );
        assert_eq!(
            "d0da0172ec63af077f816c91a25a5ecefc7a8a0ad48ce8b4de828646c87f7cdc",
            hex::encode(&out2[..len])
        );
        assert_eq!(&[0u8; 0], out3);
    }
}
