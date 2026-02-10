use crate::cipher::CipherState;
use std::error::Error;

pub struct TransportState {
    initiator: bool,
    cipher1:   CipherState,
    cipher2:   CipherState,
}

impl TransportState {
    pub(crate) fn new(initiator: bool, cipher1: CipherState, cipher2: CipherState) -> Self {
        Self { initiator, cipher1, cipher2 }
    }

    /// # Errors
    ///
    /// Will return `Err` if encryption fails
    pub fn encrypt(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        if self.initiator {
            self.cipher1.encrypt(&[0u8; 0], payload, message)
        } else {
            self.cipher2.encrypt(&[0u8; 0], payload, message)
        }
    }

    /// # Errors
    ///
    /// Will return `Err` if decryption fails
    pub fn decrypt(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        if self.initiator {
            self.cipher2.decrypt(&[0u8; 0], payload, message)
        } else {
            self.cipher1.decrypt(&[0u8; 0], payload, message)
        }
    }
}
