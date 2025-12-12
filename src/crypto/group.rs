#![allow(unused_assignments)]

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::symmetric::{
    decrypt_aes_gcm, derive_message_key, encrypt_aes_gcm, generate_random_bytes,
};
use crate::error::{Result, SdkError};

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    pub ciphertext: Vec<u8>,
    pub chain_id: i32,
    pub iteration: i32,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderKeyState {
    chain_key: [u8; 32],
    #[zeroize(skip)]
    chain_id: i32,
    #[zeroize(skip)]
    iteration: i32,
}

impl SenderKeyState {
    pub fn new() -> Self {
        let mut chain_key = [0u8; 32];
        let random = generate_random_bytes(32);
        chain_key.copy_from_slice(&random);

        Self {
            chain_key,
            chain_id: rand::random(),
            iteration: 0,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| SdkError::Serialization(e.to_string()))
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| SdkError::Deserialization(e.to_string()))
    }

    pub fn chain_id(&self) -> i32 {
        self.chain_id
    }

    pub fn iteration(&self) -> i32 {
        self.iteration
    }
}

pub fn create_sender_key_state() -> Result<Vec<u8>> {
    let state = SenderKeyState::new();
    state.serialize()
}

pub fn encrypt_group_message(
    state_bytes: &[u8],
    plaintext: &[u8],
) -> Result<(GroupMessage, Vec<u8>)> {
    let mut state = SenderKeyState::deserialize(state_bytes)?;

    let (message_key, new_chain_key) = derive_message_key(&state.chain_key);
    state.chain_key = *new_chain_key;
    state.iteration += 1;

    let ciphertext = encrypt_aes_gcm(message_key.deref(), plaintext)?;

    let message = GroupMessage {
        ciphertext,
        chain_id: state.chain_id,
        iteration: state.iteration - 1,
    };

    let new_state = state.serialize()?;
    Ok((message, new_state))
}

pub fn decrypt_group_message(
    state_bytes: &[u8],
    target_chain_id: i32,
    target_iteration: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let state = SenderKeyState::deserialize(state_bytes)?;

    if state.chain_id != target_chain_id {
        return Err(SdkError::GroupState("Chain ID mismatch".to_string()));
    }

    let mut chain_key = state.chain_key;
    let mut current_iteration = 0;

    while current_iteration < target_iteration {
        let (_, new_chain) = derive_message_key(&chain_key);
        chain_key = *new_chain;
        current_iteration += 1;
    }

    let (message_key, _) = derive_message_key(&chain_key);
    decrypt_aes_gcm(message_key.deref(), ciphertext)
}

pub fn update_sender_key_state_after_decrypt(
    state_bytes: &[u8],
    target_iteration: i32,
) -> Result<Vec<u8>> {
    let mut state = SenderKeyState::deserialize(state_bytes)?;

    while state.iteration <= target_iteration {
        let (_, new_chain) = derive_message_key(&state.chain_key);
        state.chain_key = *new_chain;
        state.iteration += 1;
    }

    state.serialize()
}

impl Default for SenderKeyState {
    fn default() -> Self {
        Self::new()
    }
}
