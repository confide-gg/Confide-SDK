#![allow(unused_assignments)]

use std::collections::HashMap;
use std::ops::Deref;

use rand::rngs::OsRng;
use rustpq::ml_kem_hybrid::p384_mlkem1024;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::kem::{decapsulate, encapsulate, KEM_CIPHERTEXT_SIZE};
use super::symmetric::{
    decrypt_aes_gcm, derive_message_key, encrypt_aes_gcm, hkdf_derive_chain_keys, hkdf_expand,
};
use crate::error::{Result, SdkError};

const MAX_SKIP: u32 = 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    pub sender_ratchet_public: Vec<u8>,
    pub ratchet_ciphertext: Option<Vec<u8>>,
    pub previous_chain_length: u32,
    pub message_number: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
}

pub struct EncryptResult {
    pub message: EncryptedMessage,
    pub message_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RatchetState {
    #[zeroize(skip)]
    dh_public: Vec<u8>,
    dh_secret: Vec<u8>,
    #[zeroize(skip)]
    dh_remote_public: Option<Vec<u8>>,
    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    recv_chain_key: Option<[u8; 32]>,
    #[zeroize(skip)]
    send_message_number: u32,
    #[zeroize(skip)]
    recv_message_number: u32,
    #[zeroize(skip)]
    previous_chain_length: u32,
    #[zeroize(skip)]
    skipped_keys: HashMap<(Vec<u8>, u32), [u8; 32]>,
    #[zeroize(skip)]
    is_initiator: bool,
    #[zeroize(skip)]
    needs_ratchet_step: bool,
}

impl RatchetState {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| SdkError::Serialization(e.to_string()))
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| SdkError::Deserialization(e.to_string()))
    }

    pub fn encrypt_with_key(&mut self, plaintext: &[u8]) -> Result<EncryptResult> {
        let mut ratchet_ciphertext = None;

        if self.needs_ratchet_step {
            if let Some(ref remote_public) = self.dh_remote_public {
                let (new_public, new_secret) = generate_ratchet_keypair();
                let (ct, shared_secret) = encapsulate(remote_public)?;

                let (new_root, new_chain) = hkdf_derive_chain_keys(&self.root_key, &shared_secret);

                self.root_key = *new_root;
                self.send_chain_key = *new_chain;
                self.dh_public = new_public;
                self.dh_secret = new_secret;
                self.previous_chain_length = self.send_message_number;
                self.send_message_number = 0;

                ratchet_ciphertext = Some(ct);
            }
            self.needs_ratchet_step = false;
        }

        let (message_key, new_chain_key) = derive_message_key(&self.send_chain_key);
        self.send_chain_key = *new_chain_key;

        let ciphertext = encrypt_aes_gcm(message_key.deref(), plaintext)?;

        let header = MessageHeader {
            sender_ratchet_public: self.dh_public.clone(),
            ratchet_ciphertext,
            previous_chain_length: self.previous_chain_length,
            message_number: self.send_message_number,
        };

        self.send_message_number += 1;

        Ok(EncryptResult {
            message: EncryptedMessage { header, ciphertext },
            message_key: message_key.to_vec(),
        })
    }

    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        let key_id = (
            message.header.sender_ratchet_public.clone(),
            message.header.message_number,
        );
        if let Some(key) = self.skipped_keys.remove(&key_id) {
            return decrypt_aes_gcm(&key, &message.ciphertext);
        }

        let header_public = &message.header.sender_ratchet_public;

        let should_ratchet = self
            .dh_remote_public
            .as_ref()
            .map(|p| p != header_public)
            .unwrap_or(true);

        if should_ratchet {
            self.skip_message_keys(message.header.previous_chain_length)?;

            if let Some(ref ct) = message.header.ratchet_ciphertext {
                let shared_secret = decapsulate(&self.dh_secret, ct)?;

                let (new_root, new_recv_chain) =
                    hkdf_derive_chain_keys(&self.root_key, &shared_secret);

                self.root_key = *new_root;
                self.recv_chain_key = Some(*new_recv_chain);
                self.dh_remote_public = Some(header_public.clone());
                self.recv_message_number = 0;
                self.needs_ratchet_step = true;
            }
        }

        self.skip_message_keys(message.header.message_number)?;

        let recv_chain = self
            .recv_chain_key
            .as_ref()
            .ok_or(SdkError::RatchetState("No receive chain key".to_string()))?;

        let (message_key, new_recv_chain) = derive_message_key(recv_chain);
        self.recv_chain_key = Some(*new_recv_chain);
        self.recv_message_number += 1;

        decrypt_aes_gcm(message_key.deref(), &message.ciphertext)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if let Some(ref recv_chain) = self.recv_chain_key {
            let mut chain = *recv_chain;
            while self.recv_message_number < until {
                if self.skipped_keys.len() >= MAX_SKIP as usize {
                    return Err(SdkError::RatchetState(
                        "Too many skipped messages".to_string(),
                    ));
                }

                let (message_key, new_chain) = derive_message_key(&chain);
                chain = *new_chain;

                let key_id = (
                    self.dh_remote_public.clone().unwrap_or_default(),
                    self.recv_message_number,
                );
                self.skipped_keys.insert(key_id, *message_key);
                self.recv_message_number += 1;
            }
            self.recv_chain_key = Some(chain);
        }
        Ok(())
    }
}

fn generate_ratchet_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = p384_mlkem1024::generate(&mut OsRng);
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn create_initial_session(
    _our_identity_secret: &[u8],
    their_identity_public: &[u8],
    their_signed_prekey_public: &[u8],
    their_one_time_prekey_public: Option<&[u8]>,
    is_initiator: bool,
) -> Result<(RatchetState, Vec<u8>)> {
    let (ct1, ss1) = encapsulate(their_identity_public)?;
    let (ct2, ss2) = encapsulate(their_signed_prekey_public)?;

    let mut shared_secrets = Vec::with_capacity(96);
    shared_secrets.extend_from_slice(&ss1);
    shared_secrets.extend_from_slice(&ss2);

    let mut key_bundle = Vec::new();
    key_bundle.extend_from_slice(&ct1);
    key_bundle.extend_from_slice(&ct2);

    if let Some(otp_public) = their_one_time_prekey_public {
        let (ct3, ss3) = encapsulate(otp_public)?;
        shared_secrets.extend_from_slice(&ss3);
        key_bundle.extend_from_slice(&ct3);
    }

    let root_key_bytes = hkdf_expand(&shared_secrets, b"confide_x3dh_root", 32);
    let send_chain_bytes = hkdf_expand(&shared_secrets, b"confide_x3dh_chain", 32);

    let mut root_key = [0u8; 32];
    let mut send_chain_key = [0u8; 32];
    root_key.copy_from_slice(&root_key_bytes);
    send_chain_key.copy_from_slice(&send_chain_bytes);

    let (dh_public, dh_secret) = generate_ratchet_keypair();

    let state = RatchetState {
        dh_public,
        dh_secret,
        dh_remote_public: Some(their_signed_prekey_public.to_vec()),
        root_key,
        send_chain_key,
        recv_chain_key: None,
        send_message_number: 0,
        recv_message_number: 0,
        previous_chain_length: 0,
        skipped_keys: HashMap::new(),
        is_initiator,
        needs_ratchet_step: false,
    };

    Ok((state, key_bundle))
}

pub fn accept_initial_session(
    our_identity_secret: &[u8],
    our_signed_prekey_secret: &[u8],
    our_one_time_prekey_secret: Option<&[u8]>,
    _their_identity_public: &[u8],
    key_bundle: &[u8],
) -> Result<RatchetState> {
    let min_bundle_size = KEM_CIPHERTEXT_SIZE * 2;
    if key_bundle.len() < min_bundle_size {
        return Err(SdkError::InvalidKeyBundle);
    }

    let ct1 = &key_bundle[..KEM_CIPHERTEXT_SIZE];
    let ct2 = &key_bundle[KEM_CIPHERTEXT_SIZE..KEM_CIPHERTEXT_SIZE * 2];

    let ss1 = decapsulate(our_identity_secret, ct1)?;
    let ss2 = decapsulate(our_signed_prekey_secret, ct2)?;

    let mut shared_secrets = Vec::with_capacity(96);
    shared_secrets.extend_from_slice(&ss1);
    shared_secrets.extend_from_slice(&ss2);

    if let Some(otp_secret) = our_one_time_prekey_secret {
        if key_bundle.len() >= KEM_CIPHERTEXT_SIZE * 3 {
            let ct3 = &key_bundle[KEM_CIPHERTEXT_SIZE * 2..KEM_CIPHERTEXT_SIZE * 3];
            let ss3 = decapsulate(otp_secret, ct3)?;
            shared_secrets.extend_from_slice(&ss3);
        }
    }

    let root_key_bytes = hkdf_expand(&shared_secrets, b"confide_x3dh_root", 32);
    let recv_chain_bytes = hkdf_expand(&shared_secrets, b"confide_x3dh_chain", 32);

    let mut root_key = [0u8; 32];
    let mut recv_chain_key = [0u8; 32];
    root_key.copy_from_slice(&root_key_bytes);
    recv_chain_key.copy_from_slice(&recv_chain_bytes);

    let (dh_public, dh_secret) = generate_ratchet_keypair();

    Ok(RatchetState {
        dh_public,
        dh_secret,
        dh_remote_public: None,
        root_key,
        send_chain_key: [0u8; 32],
        recv_chain_key: Some(recv_chain_key),
        send_message_number: 0,
        recv_message_number: 0,
        previous_chain_length: 0,
        skipped_keys: HashMap::new(),
        is_initiator: false,
        needs_ratchet_step: true,
    })
}
