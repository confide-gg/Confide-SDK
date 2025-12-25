#![allow(unused_assignments)]

use rand::rngs::OsRng;
use rustpq::ml_kem_hybrid::p384_mlkem1024;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::keys::DsaKeyPair;
use super::symmetric::hkdf_expand;
use crate::error::{Result, SdkError};

pub const CALL_ID_SIZE: usize = 16;
const KEM_CIPHERTEXT_SIZE: usize = 1665;

#[derive(Clone, Serialize, Deserialize)]
pub struct CallOffer {
    pub call_id: [u8; CALL_ID_SIZE],
    pub caller_id: [u8; CALL_ID_SIZE],
    pub callee_id: [u8; CALL_ID_SIZE],
    pub ephemeral_kem_public: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CallAnswer {
    pub call_id: [u8; CALL_ID_SIZE],
    pub ephemeral_kem_public: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CallKeyExchangeComplete {
    pub call_id: [u8; CALL_ID_SIZE],
    pub kem_ciphertext: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CallKeyPair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl CallKeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = p384_mlkem1024::generate(&mut OsRng);
        Self {
            public: pk.as_bytes().to_vec(),
            secret: sk.as_bytes().to_vec(),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CallMediaKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

pub struct CallEncryptor {
    media_keys: CallMediaKeys,
    is_caller: bool,
    send_nonce_counter: u64,
    recv_nonce_counter: u64,
    video_send_nonce_counter: u64,
    video_recv_nonce_counter: u64,
}

impl CallEncryptor {
    pub fn new(media_keys: CallMediaKeys, is_caller: bool) -> Self {
        Self {
            media_keys,
            is_caller,
            send_nonce_counter: 0,
            recv_nonce_counter: 0,
            video_send_nonce_counter: 0,
            video_recv_nonce_counter: 0,
        }
    }

    pub fn reset_video_send_counter(&mut self) {
        self.video_send_nonce_counter = 0;
    }

    pub fn reset_video_recv_counter(&mut self) {
        self.video_recv_nonce_counter = 0;
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = if self.is_caller {
            &self.media_keys.send_key
        } else {
            &self.media_keys.recv_key
        };

        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.send_nonce_counter.to_be_bytes());
        self.send_nonce_counter += 1;

        encrypt_with_nonce(key, &nonce, plaintext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = if self.is_caller {
            &self.media_keys.recv_key
        } else {
            &self.media_keys.send_key
        };

        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.recv_nonce_counter.to_be_bytes());
        self.recv_nonce_counter += 1;

        decrypt_with_nonce(key, &nonce, ciphertext)
    }

    pub fn encrypt_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(plaintext)
    }

    pub fn decrypt_frame(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt(ciphertext)
    }

    pub fn encrypt_video_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = if self.is_caller {
            &self.media_keys.send_key
        } else {
            &self.media_keys.recv_key
        };

        let mut nonce = [0u8; 12];
        nonce[0] = 0x02;
        nonce[4..].copy_from_slice(&self.video_send_nonce_counter.to_be_bytes());
        self.video_send_nonce_counter += 1;

        encrypt_with_nonce(key, &nonce, plaintext)
    }

    pub fn decrypt_video_frame(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = if self.is_caller {
            &self.media_keys.recv_key
        } else {
            &self.media_keys.send_key
        };

        let mut nonce = [0u8; 12];
        nonce[0] = 0x02;
        nonce[4..].copy_from_slice(&self.video_recv_nonce_counter.to_be_bytes());
        self.video_recv_nonce_counter += 1;

        decrypt_with_nonce(key, &nonce, ciphertext)
    }
}

pub fn create_call_offer(
    call_id: [u8; CALL_ID_SIZE],
    caller_id: [u8; CALL_ID_SIZE],
    callee_id: [u8; CALL_ID_SIZE],
    dsa: &DsaKeyPair,
) -> Result<(CallKeyPair, CallOffer)> {
    let ephemeral = CallKeyPair::generate();

    let mut sign_data = Vec::with_capacity(CALL_ID_SIZE * 3 + ephemeral.public.len());
    sign_data.extend_from_slice(&call_id);
    sign_data.extend_from_slice(&caller_id);
    sign_data.extend_from_slice(&callee_id);
    sign_data.extend_from_slice(&ephemeral.public);

    let signature = dsa.sign(&sign_data)?;

    let offer = CallOffer {
        call_id,
        caller_id,
        callee_id,
        ephemeral_kem_public: ephemeral.public.clone(),
        signature,
    };

    Ok((ephemeral, offer))
}

pub fn accept_call_offer(
    offer: &CallOffer,
    our_dsa: &DsaKeyPair,
    caller_identity_public: &[u8],
) -> Result<(CallKeyPair, CallAnswer, Vec<u8>)> {
    let mut sign_data = Vec::with_capacity(CALL_ID_SIZE * 3 + offer.ephemeral_kem_public.len());
    sign_data.extend_from_slice(&offer.call_id);
    sign_data.extend_from_slice(&offer.caller_id);
    sign_data.extend_from_slice(&offer.callee_id);
    sign_data.extend_from_slice(&offer.ephemeral_kem_public);

    let valid = DsaKeyPair::verify(caller_identity_public, &sign_data, &offer.signature)?;
    if !valid {
        return Err(SdkError::SignatureVerificationFailed);
    }

    let callee_ephemeral = CallKeyPair::generate();

    let caller_pk = p384_mlkem1024::PublicKey::from_bytes(&offer.ephemeral_kem_public)
        .map_err(|_| SdkError::Kem("Invalid caller ephemeral public key".to_string()))?;
    let (ct, ss) = p384_mlkem1024::encapsulate(&caller_pk, &mut OsRng);
    let shared_secret_1 = ss.derive_key();

    let mut answer_sign_data =
        Vec::with_capacity(CALL_ID_SIZE + callee_ephemeral.public.len() + KEM_CIPHERTEXT_SIZE);
    answer_sign_data.extend_from_slice(&offer.call_id);
    answer_sign_data.extend_from_slice(&callee_ephemeral.public);
    let ct_bytes = ct.as_bytes();
    answer_sign_data.extend_from_slice(&ct_bytes);

    let signature = our_dsa.sign(&answer_sign_data)?;

    let answer = CallAnswer {
        call_id: offer.call_id,
        ephemeral_kem_public: callee_ephemeral.public.clone(),
        kem_ciphertext: ct_bytes.to_vec(),
        signature,
    };

    Ok((callee_ephemeral, answer, shared_secret_1.to_vec()))
}

pub fn complete_call_key_exchange_caller(
    answer: &CallAnswer,
    caller_ephemeral: &CallKeyPair,
    callee_identity_public: &[u8],
) -> Result<(CallKeyExchangeComplete, CallMediaKeys)> {
    let mut sign_data = Vec::with_capacity(
        CALL_ID_SIZE + answer.ephemeral_kem_public.len() + answer.kem_ciphertext.len(),
    );
    sign_data.extend_from_slice(&answer.call_id);
    sign_data.extend_from_slice(&answer.ephemeral_kem_public);
    sign_data.extend_from_slice(&answer.kem_ciphertext);

    let valid = DsaKeyPair::verify(callee_identity_public, &sign_data, &answer.signature)?;
    if !valid {
        return Err(SdkError::SignatureVerificationFailed);
    }

    let caller_sk = p384_mlkem1024::SecretKey::from_bytes(&caller_ephemeral.secret)
        .map_err(|_| SdkError::Kem("Invalid caller secret key".to_string()))?;
    let ct1 = p384_mlkem1024::Ciphertext::from_bytes(&answer.kem_ciphertext)
        .map_err(|_| SdkError::InvalidCiphertext)?;
    let ss1 = p384_mlkem1024::decapsulate(&caller_sk, &ct1);
    let shared_secret_1 = ss1.derive_key();

    let callee_pk = p384_mlkem1024::PublicKey::from_bytes(&answer.ephemeral_kem_public)
        .map_err(|_| SdkError::Kem("Invalid callee ephemeral public key".to_string()))?;
    let (ct2, ss2) = p384_mlkem1024::encapsulate(&callee_pk, &mut OsRng);
    let shared_secret_2 = ss2.derive_key();

    let media_keys = derive_media_keys(&shared_secret_1, &shared_secret_2);

    let key_complete = CallKeyExchangeComplete {
        call_id: answer.call_id,
        kem_ciphertext: ct2.as_bytes().to_vec(),
    };

    Ok((key_complete, media_keys))
}

pub fn complete_call_key_exchange_callee(
    key_complete: &CallKeyExchangeComplete,
    callee_ephemeral: &CallKeyPair,
    shared_secret_1: &[u8],
) -> Result<CallMediaKeys> {
    if shared_secret_1.len() != 32 {
        return Err(SdkError::InvalidKeyLength {
            expected: 32,
            actual: shared_secret_1.len(),
        });
    }

    let callee_sk = p384_mlkem1024::SecretKey::from_bytes(&callee_ephemeral.secret)
        .map_err(|_| SdkError::Kem("Invalid callee secret key".to_string()))?;
    let ct2 = p384_mlkem1024::Ciphertext::from_bytes(&key_complete.kem_ciphertext)
        .map_err(|_| SdkError::InvalidCiphertext)?;
    let ss2 = p384_mlkem1024::decapsulate(&callee_sk, &ct2);
    let shared_secret_2 = ss2.derive_key();

    let mut ss1_arr = [0u8; 32];
    ss1_arr.copy_from_slice(shared_secret_1);
    Ok(derive_media_keys(&ss1_arr, &shared_secret_2))
}

fn derive_media_keys(shared_secret_1: &[u8; 32], shared_secret_2: &[u8; 32]) -> CallMediaKeys {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(shared_secret_1);
    combined.extend_from_slice(shared_secret_2);

    let caller_send_key = hkdf_expand(&combined, b"confide_call_caller_send", 32);
    let callee_send_key = hkdf_expand(&combined, b"confide_call_callee_send", 32);

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];

    send_key.copy_from_slice(&caller_send_key);
    recv_key.copy_from_slice(&callee_send_key);

    CallMediaKeys { send_key, recv_key }
}

fn encrypt_with_nonce(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Encryption(format!("Failed to create cipher: {}", e)))?;

    cipher
        .encrypt(&Nonce::from(*nonce), plaintext)
        .map_err(|e| SdkError::Encryption(format!("AES-GCM encryption failed: {}", e)))
}

fn decrypt_with_nonce(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Decryption(format!("Failed to create cipher: {}", e)))?;

    cipher
        .decrypt(&Nonce::from(*nonce), ciphertext)
        .map_err(|e| SdkError::Decryption(format!("AES-GCM decryption failed: {}", e)))
}
