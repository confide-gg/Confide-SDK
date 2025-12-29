#![allow(unused_assignments)]

use std::collections::HashMap;

use rand::rngs::OsRng;
use rustpq::ml_kem_hybrid::p384_mlkem1024;

use super::call::CallKeyPair;
use super::crypto::{decrypt_with_key, encrypt_with_key};
use super::keys::{GroupCallRecvSenderKey, GroupCallSenderKey, GroupCallSenderKeyState};
use super::messages::{
    GroupCallAnnounce, GroupCallJoin, GroupCallKeyRotation, GroupCallLeave,
    GroupCallSenderKeyDistribution,
};
use super::participant::{GroupCallParticipant, GroupCallParticipantState};
use super::state::GroupCallState;
use super::types::{GroupCallId, ParticipantId, MAX_GROUP_CALL_PARTICIPANTS};
use crate::crypto::keys::DsaKeyPair;
use crate::error::{Result, SdkError};

pub fn create_group_call(
    our_participant_id: ParticipantId,
    our_identity_public: Vec<u8>,
    our_dsa: &DsaKeyPair,
) -> Result<(GroupCallState, GroupCallAnnounce)> {
    let call_id = GroupCallId::new();
    let ephemeral = CallKeyPair::generate();
    let sender_key_state = GroupCallSenderKeyState::new();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(call_id.as_bytes());
    sign_data.extend_from_slice(our_participant_id.as_bytes());
    sign_data.extend_from_slice(&our_identity_public);
    sign_data.extend_from_slice(&ephemeral.public);
    sign_data.extend_from_slice(&timestamp.to_be_bytes());

    let signature = our_dsa.sign(&sign_data)?;

    let announce = GroupCallAnnounce {
        call_id: call_id.clone(),
        initiator_id: our_participant_id.clone(),
        initiator_identity_public: our_identity_public.clone(),
        ephemeral_kem_public: ephemeral.public.clone(),
        signature,
        timestamp,
    };

    let state = GroupCallState {
        call_id,
        our_participant_id,
        our_sender_key_state: sender_key_state,
        our_ephemeral_keypair: ephemeral,
        our_identity_public,
        participants: HashMap::new(),
        is_initiator: true,
    };

    Ok((state, announce))
}

pub fn join_group_call(
    announce: &GroupCallAnnounce,
    our_participant_id: ParticipantId,
    our_identity_public: Vec<u8>,
    our_dsa: &DsaKeyPair,
) -> Result<(GroupCallState, GroupCallJoin)> {
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(announce.call_id.as_bytes());
    sign_data.extend_from_slice(announce.initiator_id.as_bytes());
    sign_data.extend_from_slice(&announce.initiator_identity_public);
    sign_data.extend_from_slice(&announce.ephemeral_kem_public);
    sign_data.extend_from_slice(&announce.timestamp.to_be_bytes());

    let valid = DsaKeyPair::verify(
        &announce.initiator_identity_public,
        &sign_data,
        &announce.signature,
    )?;
    if !valid {
        return Err(SdkError::SignatureVerificationFailed);
    }

    let ephemeral = CallKeyPair::generate();
    let sender_key_state = GroupCallSenderKeyState::new();

    let mut join_sign_data = Vec::new();
    join_sign_data.extend_from_slice(announce.call_id.as_bytes());
    join_sign_data.extend_from_slice(our_participant_id.as_bytes());
    join_sign_data.extend_from_slice(&our_identity_public);
    join_sign_data.extend_from_slice(&ephemeral.public);

    let signature = our_dsa.sign(&join_sign_data)?;

    let join = GroupCallJoin {
        call_id: announce.call_id.clone(),
        participant_id: our_participant_id.clone(),
        participant_identity_public: our_identity_public.clone(),
        ephemeral_kem_public: ephemeral.public.clone(),
        signature,
    };

    let initiator_participant = GroupCallParticipant {
        participant_id: announce.initiator_id.clone(),
        identity_public_key: announce.initiator_identity_public.clone(),
        ephemeral_kem_public: announce.ephemeral_kem_public.clone(),
        joined_at: announce.timestamp,
    };

    let mut participants = HashMap::new();
    participants.insert(
        announce.initiator_id.clone(),
        GroupCallParticipantState {
            info: initiator_participant,
            sender_key: None,
        },
    );

    let state = GroupCallState {
        call_id: announce.call_id.clone(),
        our_participant_id,
        our_sender_key_state: sender_key_state,
        our_ephemeral_keypair: ephemeral,
        our_identity_public,
        participants,
        is_initiator: false,
    };

    Ok((state, join))
}

pub fn handle_participant_join(
    state: &mut GroupCallState,
    join: &GroupCallJoin,
    our_dsa: &DsaKeyPair,
) -> Result<GroupCallSenderKeyDistribution> {
    if !state.can_add_participant() {
        return Err(SdkError::GroupCallFull(MAX_GROUP_CALL_PARTICIPANTS));
    }

    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(join.call_id.as_bytes());
    sign_data.extend_from_slice(join.participant_id.as_bytes());
    sign_data.extend_from_slice(&join.participant_identity_public);
    sign_data.extend_from_slice(&join.ephemeral_kem_public);

    let valid = DsaKeyPair::verify(
        &join.participant_identity_public,
        &sign_data,
        &join.signature,
    )?;
    if !valid {
        return Err(SdkError::SignatureVerificationFailed);
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let participant = GroupCallParticipant {
        participant_id: join.participant_id.clone(),
        identity_public_key: join.participant_identity_public.clone(),
        ephemeral_kem_public: join.ephemeral_kem_public.clone(),
        joined_at: timestamp,
    };

    state.participants.insert(
        join.participant_id.clone(),
        GroupCallParticipantState {
            info: participant.clone(),
            sender_key: None,
        },
    );

    distribute_sender_key_to_participant(state, &participant, our_dsa)
}

pub fn distribute_sender_key_to_participant(
    state: &GroupCallState,
    recipient: &GroupCallParticipant,
    our_dsa: &DsaKeyPair,
) -> Result<GroupCallSenderKeyDistribution> {
    let sender_key = state.our_sender_key_state.to_sender_key();

    let recipient_pk = p384_mlkem1024::PublicKey::from_bytes(&recipient.ephemeral_kem_public)
        .map_err(|_| SdkError::Kem("Invalid recipient ephemeral public key".to_string()))?;
    let (ct, ss) = p384_mlkem1024::encapsulate(&recipient_pk, &mut OsRng);
    let shared_secret = ss.derive_key();

    let encrypted_sender_key = encrypt_with_key(&shared_secret, sender_key.key())?;

    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(state.call_id.as_bytes());
    sign_data.extend_from_slice(state.our_participant_id.as_bytes());
    sign_data.extend_from_slice(recipient.participant_id.as_bytes());
    sign_data.extend_from_slice(&ct.as_bytes());
    sign_data.extend_from_slice(&encrypted_sender_key);
    sign_data.extend_from_slice(&sender_key.key_id().to_be_bytes());

    let signature = our_dsa.sign(&sign_data)?;

    Ok(GroupCallSenderKeyDistribution {
        call_id: state.call_id.clone(),
        from_participant: state.our_participant_id.clone(),
        to_participant: recipient.participant_id.clone(),
        kem_ciphertext: ct.as_bytes().to_vec(),
        encrypted_sender_key,
        key_id: sender_key.key_id(),
        signature,
    })
}

pub fn handle_sender_key_distribution(
    state: &mut GroupCallState,
    distribution: &GroupCallSenderKeyDistribution,
    sender_identity_public: &[u8],
) -> Result<()> {
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(distribution.call_id.as_bytes());
    sign_data.extend_from_slice(distribution.from_participant.as_bytes());
    sign_data.extend_from_slice(distribution.to_participant.as_bytes());
    sign_data.extend_from_slice(&distribution.kem_ciphertext);
    sign_data.extend_from_slice(&distribution.encrypted_sender_key);
    sign_data.extend_from_slice(&distribution.key_id.to_be_bytes());

    let valid = DsaKeyPair::verify(sender_identity_public, &sign_data, &distribution.signature)?;
    if !valid {
        return Err(SdkError::SignatureVerificationFailed);
    }

    let our_sk = p384_mlkem1024::SecretKey::from_bytes(&state.our_ephemeral_keypair.secret)
        .map_err(|_| SdkError::Kem("Invalid secret key".to_string()))?;
    let ct = p384_mlkem1024::Ciphertext::from_bytes(&distribution.kem_ciphertext)
        .map_err(|_| SdkError::InvalidCiphertext)?;
    let ss = p384_mlkem1024::decapsulate(&our_sk, &ct);
    let shared_secret = ss.derive_key();

    let sender_key_bytes = decrypt_with_key(&shared_secret, &distribution.encrypted_sender_key)?;
    if sender_key_bytes.len() != 32 {
        return Err(SdkError::InvalidKeyLength {
            expected: 32,
            actual: sender_key_bytes.len(),
        });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&sender_key_bytes);

    let sender_key = GroupCallSenderKey::from_raw(key, distribution.key_id);

    if let Some(participant) = state.participants.get_mut(&distribution.from_participant) {
        participant.sender_key = Some(GroupCallRecvSenderKey::from_sender_key(&sender_key));
    } else {
        return Err(SdkError::ParticipantNotFound);
    }

    Ok(())
}

pub fn add_participant_from_existing(
    state: &mut GroupCallState,
    participant_id: ParticipantId,
    identity_public_key: Vec<u8>,
    ephemeral_kem_public: Vec<u8>,
    joined_at: u64,
) -> Result<()> {
    if !state.can_add_participant() {
        return Err(SdkError::GroupCallFull(MAX_GROUP_CALL_PARTICIPANTS));
    }

    let participant = GroupCallParticipant {
        participant_id: participant_id.clone(),
        identity_public_key,
        ephemeral_kem_public,
        joined_at,
    };

    state.participants.insert(
        participant_id,
        GroupCallParticipantState {
            info: participant,
            sender_key: None,
        },
    );

    Ok(())
}

pub fn leave_group_call(state: &GroupCallState, our_dsa: &DsaKeyPair) -> Result<GroupCallLeave> {
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(state.call_id.as_bytes());
    sign_data.extend_from_slice(state.our_participant_id.as_bytes());

    let signature = our_dsa.sign(&sign_data)?;

    Ok(GroupCallLeave {
        call_id: state.call_id.clone(),
        participant_id: state.our_participant_id.clone(),
        signature,
    })
}

pub fn handle_participant_leave(
    state: &mut GroupCallState,
    leave: &GroupCallLeave,
    leaver_identity_public: &[u8],
    our_dsa: &DsaKeyPair,
) -> Result<GroupCallKeyRotation> {
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(leave.call_id.as_bytes());
    sign_data.extend_from_slice(leave.participant_id.as_bytes());

    let valid = DsaKeyPair::verify(leaver_identity_public, &sign_data, &leave.signature)?;
    if !valid {
        return Err(SdkError::SignatureVerificationFailed);
    }

    state.participants.remove(&leave.participant_id);

    rotate_sender_key(state, our_dsa)
}

pub fn rotate_sender_key(
    state: &mut GroupCallState,
    our_dsa: &DsaKeyPair,
) -> Result<GroupCallKeyRotation> {
    state.our_sender_key_state.rotate();

    let distributions: Result<Vec<GroupCallSenderKeyDistribution>> = state
        .participants
        .values()
        .map(|p| distribute_sender_key_to_participant(state, &p.info, our_dsa))
        .collect();

    let distributions = distributions?;

    Ok(GroupCallKeyRotation {
        call_id: state.call_id.clone(),
        participant_id: state.our_participant_id.clone(),
        new_key_id: state.our_sender_key_state.key_id(),
        distributions,
    })
}

pub fn handle_key_rotation(
    state: &mut GroupCallState,
    rotation: &GroupCallKeyRotation,
    sender_identity_public: &[u8],
) -> Result<()> {
    for distribution in &rotation.distributions {
        if distribution.to_participant == state.our_participant_id {
            handle_sender_key_distribution(state, distribution, sender_identity_public)?;
            break;
        }
    }

    Ok(())
}
