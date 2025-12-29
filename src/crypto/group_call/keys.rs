#![allow(unused_assignments)]

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::symmetric::generate_random_bytes;

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupCallSenderKey {
    key: [u8; 32],
    #[zeroize(skip)]
    key_id: u32,
}

impl GroupCallSenderKey {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        let random = generate_random_bytes(32);
        key.copy_from_slice(&random);
        Self {
            key,
            key_id: rand::random(),
        }
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn from_raw(key: [u8; 32], key_id: u32) -> Self {
        Self { key, key_id }
    }
}

impl Default for GroupCallSenderKey {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupCallSenderKeyState {
    pub(crate) sender_key: [u8; 32],
    #[zeroize(skip)]
    pub(crate) key_id: u32,
    #[zeroize(skip)]
    pub(crate) audio_nonce_counter: u64,
    #[zeroize(skip)]
    pub(crate) video_nonce_counter: u64,
    #[zeroize(skip)]
    pub(crate) screenshare_nonce_counter: u64,
}

impl GroupCallSenderKeyState {
    pub fn new() -> Self {
        let sender_key = GroupCallSenderKey::new();
        Self {
            sender_key: *sender_key.key(),
            key_id: sender_key.key_id,
            audio_nonce_counter: 0,
            video_nonce_counter: 0,
            screenshare_nonce_counter: 0,
        }
    }

    pub fn from_sender_key(sender_key: &GroupCallSenderKey) -> Self {
        Self {
            sender_key: *sender_key.key(),
            key_id: sender_key.key_id,
            audio_nonce_counter: 0,
            video_nonce_counter: 0,
            screenshare_nonce_counter: 0,
        }
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn to_sender_key(&self) -> GroupCallSenderKey {
        GroupCallSenderKey {
            key: self.sender_key,
            key_id: self.key_id,
        }
    }

    pub fn rotate(&mut self) {
        let new_key = GroupCallSenderKey::new();
        self.sender_key = *new_key.key();
        self.key_id = new_key.key_id;
        self.audio_nonce_counter = 0;
        self.video_nonce_counter = 0;
        self.screenshare_nonce_counter = 0;
    }
}

impl Default for GroupCallSenderKeyState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupCallRecvSenderKey {
    pub(crate) key: [u8; 32],
    #[zeroize(skip)]
    pub(crate) key_id: u32,
    #[zeroize(skip)]
    pub(crate) audio_nonce_counter: u64,
    #[zeroize(skip)]
    pub(crate) video_nonce_counter: u64,
    #[zeroize(skip)]
    pub(crate) screenshare_nonce_counter: u64,
}

impl GroupCallRecvSenderKey {
    pub fn from_sender_key(sender_key: &GroupCallSenderKey) -> Self {
        Self {
            key: *sender_key.key(),
            key_id: sender_key.key_id,
            audio_nonce_counter: 0,
            video_nonce_counter: 0,
            screenshare_nonce_counter: 0,
        }
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn update_key(&mut self, sender_key: &GroupCallSenderKey) {
        self.key = *sender_key.key();
        self.key_id = sender_key.key_id;
        self.audio_nonce_counter = 0;
        self.video_nonce_counter = 0;
        self.screenshare_nonce_counter = 0;
    }
}
