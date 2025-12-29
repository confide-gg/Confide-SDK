#![allow(unused_assignments)]

use rand::rngs::OsRng;
use rustpq::ml_kem_hybrid::p384_mlkem1024;

use super::crypto::derive_media_keys;
use super::keys::{CallKeyPair, CallMediaKeys};
use super::messages::{CallAnswer, CallKeyExchangeComplete, CallOffer};
use super::types::{CALL_ID_SIZE, KEM_CIPHERTEXT_SIZE};
use crate::crypto::keys::DsaKeyPair;
use crate::error::{Result, SdkError};

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
