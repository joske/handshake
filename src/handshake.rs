use crate::{
    cipher::CipherState,
    dh::{from_handshake_name, DH, MAX_DH_LEN},
    pattern::{parse_handshake_patterns, Pattern},
    symmetric::SymmetricState,
};
use std::error::Error;

const TAG_LEN: usize = 16;

/// Keeps the `HandshakeState`. Only initiator side is implemented.
pub struct HandshakeState {
    symmetric_state: SymmetricState,
    s: Box<dyn DH>,
    e: Box<dyn DH>,
    rs: [u8; MAX_DH_LEN],
    re: [u8; MAX_DH_LEN],
    psk: Option<[u8; 32]>,
    patterns: Vec<Vec<Pattern>>,
    child1: CipherState,
    child2: CipherState,
    transport_mode: bool,
}

impl HandshakeState {
    /// create a new `HandshakeState` object
    /// # Errors
    ///
    /// Will return `Err` if a cryptocraphic operation fails
    pub fn new(
        handshake_name: &str,
        s: Box<dyn DH>,
        psk: &[u8],
        prologue: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        let mut patterns = parse_handshake_patterns(handshake_name);
        // patterns is reversed to be able to easily pop() the front one
        patterns.reverse();
        let mut symmetric_state = SymmetricState::new(handshake_name)?;
        symmetric_state.init(handshake_name);
        symmetric_state.mix_hash(prologue);
        let mut k = [0u8; 32];
        k.copy_from_slice(psk);
        // no pre-messages for this handshake pattern
        let e = from_handshake_name(handshake_name)?;
        Ok(Self {
            symmetric_state,
            s,
            e,
            rs: [0u8; MAX_DH_LEN],
            re: [0u8; MAX_DH_LEN],
            psk: Some(k),
            patterns,
            child1: CipherState::new(handshake_name)?,
            child2: CipherState::new(handshake_name)?,
            transport_mode: false,
        })
    }

    /// Send a message during the handshake or transmission phase
    ///
    /// # Errors
    ///
    /// Forwards any errors from the lower calls
    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        if self.transport_mode {
            self.child1.encrypt(&[0u8; 0], payload, message)
        } else {
            self.write_message_handshake(payload, message)
        }
    }

    /// Send a message during the handshake phase. Will send the next pattern in the list of patterns
    ///
    /// # Errors
    ///
    /// Will return `Err` if a cryptocraphic operation fails
    pub fn write_message_handshake(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        let mut byte_index = 0;
        if let Some(p) = self.patterns.pop() {
            for token in p {
                match token {
                    Pattern::E => {
                        self.e.generate();
                        let len = self.e.dh_len();
                        message[byte_index..byte_index + len].copy_from_slice(self.e.public());
                        byte_index += len;
                        self.symmetric_state.mix_hash(self.e.public());
                        if self.psk.is_some() {
                            self.symmetric_state.mix_key(self.e.public());
                        }
                    }
                    Pattern::S => {
                        byte_index += self
                            .symmetric_state
                            .encrypt_and_mix_hash(self.s.public(), &mut message[byte_index..])?;
                    }
                    Pattern::EE => {
                        // DH between e.private and re
                        let mut out = [0u8; MAX_DH_LEN];
                        self.e.dh(&self.re, &mut out);
                        let len = self.e.dh_len();
                        self.symmetric_state.mix_key(&out[..len]);
                    }
                    Pattern::ES => {
                        // DH between e.private and rs
                        let mut out = [0u8; MAX_DH_LEN];
                        self.e.dh(&self.rs, &mut out);
                        let len = self.e.dh_len();
                        self.symmetric_state.mix_key(&out[..len]);
                    }
                    Pattern::SE => {
                        // DH between s.private and re
                        let mut out = [0u8; MAX_DH_LEN];
                        self.s.dh(&self.re, &mut out);
                        let len = self.s.dh_len();
                        self.symmetric_state.mix_key(&out[..len]);
                    }
                    Pattern::SS => {
                        // DH between s.private and rs
                        let mut out = [0u8; MAX_DH_LEN];
                        self.s.dh(&self.rs, &mut out);
                        let len = self.s.dh_len();
                        self.symmetric_state.mix_key(&out[..len]);
                    }
                    Pattern::PSK => {
                        if let Some(psk) = self.psk {
                            self.symmetric_state.mix_key_and_hash(&psk);
                        } else {
                            return Err("PSK requested but no PSK set".into());
                        }
                    }
                }
            }
        }
        byte_index += self
            .symmetric_state
            .encrypt_and_mix_hash(payload, &mut message[byte_index..])?;

        if self.patterns.is_empty() {
            // last pattern, now split the cipher states and enable transport mode
            self.symmetric_state
                .split(&mut self.child1, &mut self.child2);
            self.transport_mode = true;
        }

        Ok(byte_index)
    }

    /// Receive a message during the handshake or transmission phase
    ///
    /// # Errors
    ///
    /// Forwards any errors from the lower calls
    pub fn read_message(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        if self.transport_mode {
            self.child2.decrypt(&[0u8; 0], message, payload)
        } else {
            self.read_message_handshake(message, payload)
        }
    }

    /// Receive a message during the handshake phase.
    ///
    /// # Errors
    ///
    /// Will return `Err` if a cryptocraphic operation fails
    pub fn read_message_handshake(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        let mut ptr = message;
        if let Some(p) = self.patterns.pop() {
            for token in p {
                match token {
                    Pattern::E => {
                        let len = self.e.dh_len();
                        self.re[..len].copy_from_slice(&ptr[..len]);
                        ptr = &ptr[len..];
                        self.symmetric_state.mix_hash(&self.re[..len]);
                        if self.psk.is_some() {
                            self.symmetric_state.mix_key(&self.re[..len]);
                        }
                    }
                    Pattern::EE => {
                        // DH between e.private and re
                        let mut out = [0u8; MAX_DH_LEN];
                        self.e.dh(&self.re, &mut out);
                        let len = self.e.dh_len();
                        self.symmetric_state.mix_key(&out[..len]);
                    }
                    Pattern::ES => {
                        // DH between e.private and rs
                        let mut out = [0u8; MAX_DH_LEN];
                        self.e.dh(&self.rs, &mut out);
                        let len = self.e.dh_len();
                        self.symmetric_state.mix_key(&out[..len]);
                    }
                    Pattern::S => {
                        let len = self.s.dh_len();
                        let data = &ptr[..len + TAG_LEN];
                        ptr = &ptr[len + TAG_LEN..];
                        self.symmetric_state
                            .decrypt_and_mix_hash(data, &mut self.rs[..len])?;
                    }
                    Pattern::SE => {
                        // DH between s.private and re
                        let mut out = [0u8; MAX_DH_LEN];
                        self.s.dh(&self.re, &mut out);
                        let len = self.s.dh_len();
                        self.symmetric_state.mix_key(&out[..len]);
                    }
                    Pattern::SS => {
                        // DH between s.private and rs
                        let mut out = [0u8; MAX_DH_LEN];
                        self.s.dh(&self.rs, &mut out);
                        let len = self.s.dh_len();
                        self.symmetric_state.mix_key(&out[..len]);
                    }
                    Pattern::PSK => {
                        if let Some(psk) = self.psk {
                            self.symmetric_state.mix_key_and_hash(&psk);
                        } else {
                            return Err("PSK requested but no PSK set".into());
                        }
                    }
                }
            }
        }
        self.symmetric_state.decrypt_and_mix_hash(ptr, payload)?;
        let len = ptr.len() - TAG_LEN;
        Ok(len)
    }
}
