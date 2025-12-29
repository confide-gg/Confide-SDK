use super::crypto::{decrypt_with_nonce, encrypt_with_nonce};
use super::keys::CallMediaKeys;
use crate::error::Result;

pub struct CallEncryptor {
    media_keys: CallMediaKeys,
    is_caller: bool,
    audio_send_nonce_counter: u64,
    audio_recv_nonce_counter: u64,
    video_send_nonce_counter: u64,
    video_recv_nonce_counter: u64,
    screenshare_send_nonce_counter: u64,
    screenshare_recv_nonce_counter: u64,
}

impl CallEncryptor {
    pub fn new(media_keys: CallMediaKeys, is_caller: bool) -> Self {
        Self {
            media_keys,
            is_caller,
            audio_send_nonce_counter: 0,
            audio_recv_nonce_counter: 0,
            video_send_nonce_counter: 0,
            video_recv_nonce_counter: 0,
            screenshare_send_nonce_counter: 0,
            screenshare_recv_nonce_counter: 0,
        }
    }

    pub fn reset_audio_counters(&mut self) {
        self.audio_send_nonce_counter = 0;
        self.audio_recv_nonce_counter = 0;
    }

    pub fn reset_video_counters(&mut self) {
        self.video_send_nonce_counter = 0;
        self.video_recv_nonce_counter = 0;
    }

    pub fn reset_screenshare_counters(&mut self) {
        self.screenshare_send_nonce_counter = 0;
        self.screenshare_recv_nonce_counter = 0;
    }

    fn send_key(&self) -> &[u8; 32] {
        if self.is_caller {
            &self.media_keys.send_key
        } else {
            &self.media_keys.recv_key
        }
    }

    fn recv_key(&self) -> &[u8; 32] {
        if self.is_caller {
            &self.media_keys.recv_key
        } else {
            &self.media_keys.send_key
        }
    }

    pub fn encrypt_audio(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[0] = 0x01;
        nonce[4..].copy_from_slice(&self.audio_send_nonce_counter.to_be_bytes());
        self.audio_send_nonce_counter += 1;
        encrypt_with_nonce(self.send_key(), &nonce, plaintext)
    }

    pub fn decrypt_audio(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[0] = 0x01;
        nonce[4..].copy_from_slice(&self.audio_recv_nonce_counter.to_be_bytes());
        self.audio_recv_nonce_counter += 1;
        decrypt_with_nonce(self.recv_key(), &nonce, ciphertext)
    }

    pub fn encrypt_video(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[0] = 0x02;
        nonce[4..].copy_from_slice(&self.video_send_nonce_counter.to_be_bytes());
        self.video_send_nonce_counter += 1;
        encrypt_with_nonce(self.send_key(), &nonce, plaintext)
    }

    pub fn decrypt_video(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[0] = 0x02;
        nonce[4..].copy_from_slice(&self.video_recv_nonce_counter.to_be_bytes());
        self.video_recv_nonce_counter += 1;
        decrypt_with_nonce(self.recv_key(), &nonce, ciphertext)
    }

    pub fn encrypt_screenshare(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[0] = 0x03;
        nonce[4..].copy_from_slice(&self.screenshare_send_nonce_counter.to_be_bytes());
        self.screenshare_send_nonce_counter += 1;
        encrypt_with_nonce(self.send_key(), &nonce, plaintext)
    }

    pub fn decrypt_screenshare(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[0] = 0x03;
        nonce[4..].copy_from_slice(&self.screenshare_recv_nonce_counter.to_be_bytes());
        self.screenshare_recv_nonce_counter += 1;
        decrypt_with_nonce(self.recv_key(), &nonce, ciphertext)
    }
}
