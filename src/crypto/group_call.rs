#![allow(unused_assignments)]

use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rngs::OsRng;
use rustpq::ml_kem_hybrid::p384_mlkem1024;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::call::CallKeyPair;
use super::keys::DsaKeyPair;
use super::symmetric::generate_random_bytes;
use crate::error::{Result, SdkError};

pub const MAX_GROUP_CALL_PARTICIPANTS: usize = 10;
pub const GROUP_CALL_ID_SIZE: usize = 16;
pub const PARTICIPANT_ID_SIZE: usize = 16;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupCallId(pub [u8; GROUP_CALL_ID_SIZE]);

impl GroupCallId {
    pub fn new() -> Self {
        let mut id = [0u8; GROUP_CALL_ID_SIZE];
        let random = generate_random_bytes(GROUP_CALL_ID_SIZE);
        id.copy_from_slice(&random);
        Self(id)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != GROUP_CALL_ID_SIZE {
            return Err(SdkError::InvalidKeyLength {
                expected: GROUP_CALL_ID_SIZE,
                actual: bytes.len(),
            });
        }
        let mut id = [0u8; GROUP_CALL_ID_SIZE];
        id.copy_from_slice(bytes);
        Ok(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for GroupCallId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub [u8; PARTICIPANT_ID_SIZE]);

impl ParticipantId {
    pub fn new() -> Self {
        let mut id = [0u8; PARTICIPANT_ID_SIZE];
        let random = generate_random_bytes(PARTICIPANT_ID_SIZE);
        id.copy_from_slice(&random);
        Self(id)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PARTICIPANT_ID_SIZE {
            return Err(SdkError::InvalidKeyLength {
                expected: PARTICIPANT_ID_SIZE,
                actual: bytes.len(),
            });
        }
        let mut id = [0u8; PARTICIPANT_ID_SIZE];
        id.copy_from_slice(bytes);
        Ok(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for ParticipantId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    Audio = 1,
    Video = 2,
}

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
}

impl Default for GroupCallSenderKey {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupCallSenderKeyState {
    sender_key: [u8; 32],
    #[zeroize(skip)]
    key_id: u32,
    #[zeroize(skip)]
    audio_nonce_counter: u64,
    #[zeroize(skip)]
    video_nonce_counter: u64,
}

impl GroupCallSenderKeyState {
    pub fn new() -> Self {
        let sender_key = GroupCallSenderKey::new();
        Self {
            sender_key: sender_key.key,
            key_id: sender_key.key_id,
            audio_nonce_counter: 0,
            video_nonce_counter: 0,
        }
    }

    pub fn from_sender_key(sender_key: &GroupCallSenderKey) -> Self {
        Self {
            sender_key: sender_key.key,
            key_id: sender_key.key_id,
            audio_nonce_counter: 0,
            video_nonce_counter: 0,
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
        self.sender_key = new_key.key;
        self.key_id = new_key.key_id;
        self.audio_nonce_counter = 0;
        self.video_nonce_counter = 0;
    }
}

impl Default for GroupCallSenderKeyState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupCallRecvSenderKey {
    key: [u8; 32],
    #[zeroize(skip)]
    key_id: u32,
    #[zeroize(skip)]
    audio_nonce_counter: u64,
    #[zeroize(skip)]
    video_nonce_counter: u64,
}

impl GroupCallRecvSenderKey {
    pub fn from_sender_key(sender_key: &GroupCallSenderKey) -> Self {
        Self {
            key: sender_key.key,
            key_id: sender_key.key_id,
            audio_nonce_counter: 0,
            video_nonce_counter: 0,
        }
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn update_key(&mut self, sender_key: &GroupCallSenderKey) {
        self.key = sender_key.key;
        self.key_id = sender_key.key_id;
        self.audio_nonce_counter = 0;
        self.video_nonce_counter = 0;
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallParticipant {
    pub participant_id: ParticipantId,
    pub identity_public_key: Vec<u8>,
    pub ephemeral_kem_public: Vec<u8>,
    pub joined_at: u64,
}

pub struct GroupCallParticipantState {
    pub info: GroupCallParticipant,
    pub sender_key: Option<GroupCallRecvSenderKey>,
}

pub struct GroupCallState {
    call_id: GroupCallId,
    our_participant_id: ParticipantId,
    our_sender_key_state: GroupCallSenderKeyState,
    our_ephemeral_keypair: CallKeyPair,
    our_identity_public: Vec<u8>,
    participants: HashMap<ParticipantId, GroupCallParticipantState>,
    is_initiator: bool,
}

impl GroupCallState {
    pub fn call_id(&self) -> &GroupCallId {
        &self.call_id
    }

    pub fn our_participant_id(&self) -> &ParticipantId {
        &self.our_participant_id
    }

    pub fn participants(&self) -> &HashMap<ParticipantId, GroupCallParticipantState> {
        &self.participants
    }

    pub fn participant_count(&self) -> usize {
        self.participants.len() + 1
    }

    pub fn can_add_participant(&self) -> bool {
        self.participant_count() < MAX_GROUP_CALL_PARTICIPANTS
    }

    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    pub fn our_ephemeral_public(&self) -> &[u8] {
        &self.our_ephemeral_keypair.public
    }

    pub fn our_sender_key(&self) -> GroupCallSenderKey {
        self.our_sender_key_state.to_sender_key()
    }

    pub fn our_identity_public(&self) -> &[u8] {
        &self.our_identity_public
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallAnnounce {
    pub call_id: GroupCallId,
    pub initiator_id: ParticipantId,
    pub initiator_identity_public: Vec<u8>,
    pub ephemeral_kem_public: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallJoin {
    pub call_id: GroupCallId,
    pub participant_id: ParticipantId,
    pub participant_identity_public: Vec<u8>,
    pub ephemeral_kem_public: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallSenderKeyDistribution {
    pub call_id: GroupCallId,
    pub from_participant: ParticipantId,
    pub to_participant: ParticipantId,
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_sender_key: Vec<u8>,
    pub key_id: u32,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallLeave {
    pub call_id: GroupCallId,
    pub participant_id: ParticipantId,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallKeyRotation {
    pub call_id: GroupCallId,
    pub participant_id: ParticipantId,
    pub new_key_id: u32,
    pub distributions: Vec<GroupCallSenderKeyDistribution>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallMediaFrame {
    pub sender_id: ParticipantId,
    pub key_id: u32,
    pub media_type: MediaType,
    pub nonce_counter: u64,
    pub ciphertext: Vec<u8>,
}

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

    let encrypted_sender_key = encrypt_with_key(&shared_secret, &sender_key.key)?;

    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(state.call_id.as_bytes());
    sign_data.extend_from_slice(state.our_participant_id.as_bytes());
    sign_data.extend_from_slice(recipient.participant_id.as_bytes());
    sign_data.extend_from_slice(&ct.as_bytes());
    sign_data.extend_from_slice(&encrypted_sender_key);
    sign_data.extend_from_slice(&sender_key.key_id.to_be_bytes());

    let signature = our_dsa.sign(&sign_data)?;

    Ok(GroupCallSenderKeyDistribution {
        call_id: state.call_id.clone(),
        from_participant: state.our_participant_id.clone(),
        to_participant: recipient.participant_id.clone(),
        kem_ciphertext: ct.as_bytes().to_vec(),
        encrypted_sender_key,
        key_id: sender_key.key_id,
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

    let sender_key = GroupCallSenderKey {
        key,
        key_id: distribution.key_id,
    };

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

pub fn encrypt_group_call_audio(
    state: &mut GroupCallState,
    plaintext: &[u8],
) -> Result<GroupCallMediaFrame> {
    encrypt_media_frame(state, plaintext, MediaType::Audio)
}

pub fn encrypt_group_call_video(
    state: &mut GroupCallState,
    plaintext: &[u8],
) -> Result<GroupCallMediaFrame> {
    encrypt_media_frame(state, plaintext, MediaType::Video)
}

pub fn decrypt_group_call_audio(
    state: &mut GroupCallState,
    frame: &GroupCallMediaFrame,
) -> Result<Vec<u8>> {
    if frame.media_type != MediaType::Audio {
        return Err(SdkError::GroupCall("Expected audio frame".to_string()));
    }
    decrypt_media_frame(state, frame)
}

pub fn decrypt_group_call_video(
    state: &mut GroupCallState,
    frame: &GroupCallMediaFrame,
) -> Result<Vec<u8>> {
    if frame.media_type != MediaType::Video {
        return Err(SdkError::GroupCall("Expected video frame".to_string()));
    }
    decrypt_media_frame(state, frame)
}

fn encrypt_media_frame(
    state: &mut GroupCallState,
    plaintext: &[u8],
    media_type: MediaType,
) -> Result<GroupCallMediaFrame> {
    let (counter, prefix) = match media_type {
        MediaType::Audio => (&mut state.our_sender_key_state.audio_nonce_counter, 0x01u8),
        MediaType::Video => (&mut state.our_sender_key_state.video_nonce_counter, 0x02u8),
    };

    let mut nonce = [0u8; 12];
    nonce[0] = prefix;
    nonce[4..].copy_from_slice(&counter.to_be_bytes());

    let current_counter = *counter;
    *counter += 1;

    let ciphertext = encrypt_with_nonce(&state.our_sender_key_state.sender_key, &nonce, plaintext)?;

    Ok(GroupCallMediaFrame {
        sender_id: state.our_participant_id.clone(),
        key_id: state.our_sender_key_state.key_id,
        media_type,
        nonce_counter: current_counter,
        ciphertext,
    })
}

fn decrypt_media_frame(state: &mut GroupCallState, frame: &GroupCallMediaFrame) -> Result<Vec<u8>> {
    let participant = state
        .participants
        .get_mut(&frame.sender_id)
        .ok_or(SdkError::ParticipantNotFound)?;

    let recv_key = participant
        .sender_key
        .as_mut()
        .ok_or_else(|| SdkError::GroupCall("No sender key for participant".to_string()))?;

    if frame.key_id != recv_key.key_id {
        return Err(SdkError::KeyIdMismatch);
    }

    let (expected_counter, prefix) = match frame.media_type {
        MediaType::Audio => (&mut recv_key.audio_nonce_counter, 0x01u8),
        MediaType::Video => (&mut recv_key.video_nonce_counter, 0x02u8),
    };

    if frame.nonce_counter < *expected_counter {
        return Err(SdkError::ReplayAttack);
    }

    let mut nonce = [0u8; 12];
    nonce[0] = prefix;
    nonce[4..].copy_from_slice(&frame.nonce_counter.to_be_bytes());

    let plaintext = decrypt_with_nonce(&recv_key.key, &nonce, &frame.ciphertext)?;

    *expected_counter = frame.nonce_counter + 1;

    Ok(plaintext)
}

fn encrypt_with_nonce(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Encryption(format!("Failed to create cipher: {}", e)))?;

    cipher
        .encrypt(&Nonce::from(*nonce), plaintext)
        .map_err(|e| SdkError::Encryption(format!("AES-GCM encryption failed: {}", e)))
}

fn decrypt_with_nonce(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Decryption(format!("Failed to create cipher: {}", e)))?;

    cipher
        .decrypt(&Nonce::from(*nonce), ciphertext)
        .map_err(|e| SdkError::Decryption(format!("AES-GCM decryption failed: {}", e)))
}

fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = generate_random_bytes(12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Encryption(format!("Failed to create cipher: {}", e)))?;

    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|e| SdkError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_with_key(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(SdkError::Decryption("Data too short".to_string()));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Decryption(format!("Failed to create cipher: {}", e)))?;

    cipher
        .decrypt(&Nonce::from(nonce), ciphertext)
        .map_err(|e| SdkError::Decryption(format!("AES-GCM decryption failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_join_group_call() {
        let initiator_dsa = DsaKeyPair::generate();
        let initiator_dsa_pub = initiator_dsa.public.clone();
        let joiner_dsa = DsaKeyPair::generate();
        let joiner_dsa_pub = joiner_dsa.public.clone();

        let initiator_id = ParticipantId::new();
        let joiner_id = ParticipantId::new();

        let (mut initiator_state, announce) = create_group_call(
            initiator_id.clone(),
            initiator_dsa_pub.clone(),
            &initiator_dsa,
        )
        .unwrap();

        let (mut joiner_state, join) = join_group_call(
            &announce,
            joiner_id.clone(),
            joiner_dsa_pub.clone(),
            &joiner_dsa,
        )
        .unwrap();

        let initiator_key_dist =
            handle_participant_join(&mut initiator_state, &join, &initiator_dsa).unwrap();

        let joiner_key_dist = distribute_sender_key_to_participant(
            &joiner_state,
            &GroupCallParticipant {
                participant_id: initiator_id.clone(),
                identity_public_key: initiator_dsa_pub.clone(),
                ephemeral_kem_public: announce.ephemeral_kem_public.clone(),
                joined_at: announce.timestamp,
            },
            &joiner_dsa,
        )
        .unwrap();

        handle_sender_key_distribution(&mut joiner_state, &initiator_key_dist, &initiator_dsa_pub)
            .unwrap();
        handle_sender_key_distribution(&mut initiator_state, &joiner_key_dist, &joiner_dsa_pub)
            .unwrap();

        assert_eq!(initiator_state.participant_count(), 2);
        assert_eq!(joiner_state.participant_count(), 2);
    }

    #[test]
    fn test_media_encryption_decryption() {
        let initiator_dsa = DsaKeyPair::generate();
        let initiator_dsa_pub = initiator_dsa.public.clone();
        let joiner_dsa = DsaKeyPair::generate();
        let joiner_dsa_pub = joiner_dsa.public.clone();

        let initiator_id = ParticipantId::new();
        let joiner_id = ParticipantId::new();

        let (mut initiator_state, announce) = create_group_call(
            initiator_id.clone(),
            initiator_dsa_pub.clone(),
            &initiator_dsa,
        )
        .unwrap();

        let (mut joiner_state, join) = join_group_call(
            &announce,
            joiner_id.clone(),
            joiner_dsa_pub.clone(),
            &joiner_dsa,
        )
        .unwrap();

        let initiator_key_dist =
            handle_participant_join(&mut initiator_state, &join, &initiator_dsa).unwrap();

        let joiner_key_dist = distribute_sender_key_to_participant(
            &joiner_state,
            &GroupCallParticipant {
                participant_id: initiator_id.clone(),
                identity_public_key: initiator_dsa_pub.clone(),
                ephemeral_kem_public: announce.ephemeral_kem_public.clone(),
                joined_at: announce.timestamp,
            },
            &joiner_dsa,
        )
        .unwrap();

        handle_sender_key_distribution(&mut joiner_state, &initiator_key_dist, &initiator_dsa_pub)
            .unwrap();
        handle_sender_key_distribution(&mut initiator_state, &joiner_key_dist, &joiner_dsa_pub)
            .unwrap();

        let audio_data = b"Hello, this is audio!";
        let frame = encrypt_group_call_audio(&mut initiator_state, audio_data).unwrap();
        let decrypted = decrypt_group_call_audio(&mut joiner_state, &frame).unwrap();
        assert_eq!(decrypted, audio_data);

        let video_data = b"Video frame data here";
        let video_frame = encrypt_group_call_video(&mut initiator_state, video_data).unwrap();
        let decrypted_video = decrypt_group_call_video(&mut joiner_state, &video_frame).unwrap();
        assert_eq!(decrypted_video, video_data);
    }

    #[test]
    fn test_key_rotation_on_leave() {
        let dsa1 = DsaKeyPair::generate();
        let dsa_pub1 = dsa1.public.clone();
        let dsa2 = DsaKeyPair::generate();
        let dsa_pub2 = dsa2.public.clone();
        let dsa3 = DsaKeyPair::generate();
        let dsa_pub3 = dsa3.public.clone();

        let id1 = ParticipantId::new();
        let id2 = ParticipantId::new();
        let id3 = ParticipantId::new();

        let (mut state1, announce) =
            create_group_call(id1.clone(), dsa_pub1.clone(), &dsa1).unwrap();

        let (mut state2, join2) =
            join_group_call(&announce, id2.clone(), dsa_pub2.clone(), &dsa2).unwrap();
        let key_dist_1_to_2 = handle_participant_join(&mut state1, &join2, &dsa1).unwrap();
        let key_dist_2_to_1 = distribute_sender_key_to_participant(
            &state2,
            &GroupCallParticipant {
                participant_id: id1.clone(),
                identity_public_key: dsa_pub1.clone(),
                ephemeral_kem_public: announce.ephemeral_kem_public.clone(),
                joined_at: announce.timestamp,
            },
            &dsa2,
        )
        .unwrap();
        handle_sender_key_distribution(&mut state2, &key_dist_1_to_2, &dsa_pub1).unwrap();
        handle_sender_key_distribution(&mut state1, &key_dist_2_to_1, &dsa_pub2).unwrap();

        let (mut state3, join3) =
            join_group_call(&announce, id3.clone(), dsa_pub3.clone(), &dsa3).unwrap();
        let key_dist_1_to_3 = handle_participant_join(&mut state1, &join3, &dsa1).unwrap();
        add_participant_from_existing(
            &mut state2,
            id3.clone(),
            dsa_pub3.clone(),
            join3.ephemeral_kem_public.clone(),
            0,
        )
        .unwrap();
        let key_dist_2_to_3 = distribute_sender_key_to_participant(
            &state2,
            &GroupCallParticipant {
                participant_id: id3.clone(),
                identity_public_key: dsa_pub3.clone(),
                ephemeral_kem_public: join3.ephemeral_kem_public.clone(),
                joined_at: 0,
            },
            &dsa2,
        )
        .unwrap();
        add_participant_from_existing(
            &mut state3,
            id2.clone(),
            dsa_pub2.clone(),
            state2.our_ephemeral_public().to_vec(),
            0,
        )
        .unwrap();
        let key_dist_3_to_1 = distribute_sender_key_to_participant(
            &state3,
            &GroupCallParticipant {
                participant_id: id1.clone(),
                identity_public_key: dsa_pub1.clone(),
                ephemeral_kem_public: announce.ephemeral_kem_public.clone(),
                joined_at: announce.timestamp,
            },
            &dsa3,
        )
        .unwrap();
        let key_dist_3_to_2 = distribute_sender_key_to_participant(
            &state3,
            &GroupCallParticipant {
                participant_id: id2.clone(),
                identity_public_key: dsa_pub2.clone(),
                ephemeral_kem_public: state2.our_ephemeral_public().to_vec(),
                joined_at: 0,
            },
            &dsa3,
        )
        .unwrap();

        handle_sender_key_distribution(&mut state3, &key_dist_1_to_3, &dsa_pub1).unwrap();
        handle_sender_key_distribution(&mut state3, &key_dist_2_to_3, &dsa_pub2).unwrap();
        handle_sender_key_distribution(&mut state1, &key_dist_3_to_1, &dsa_pub3).unwrap();
        handle_sender_key_distribution(&mut state2, &key_dist_3_to_2, &dsa_pub3).unwrap();

        assert_eq!(state1.participant_count(), 3);
        assert_eq!(state2.participant_count(), 3);
        assert_eq!(state3.participant_count(), 3);

        let old_key_id_1 = state1.our_sender_key_state.key_id;

        let leave = leave_group_call(&state3, &dsa3).unwrap();
        let rotation1 = handle_participant_leave(&mut state1, &leave, &dsa_pub3, &dsa1).unwrap();
        let rotation2 = handle_participant_leave(&mut state2, &leave, &dsa_pub3, &dsa2).unwrap();

        assert!(state1.our_sender_key_state.key_id != old_key_id_1);
        assert_eq!(state1.participant_count(), 2);
        assert_eq!(state2.participant_count(), 2);

        handle_key_rotation(&mut state2, &rotation1, &dsa_pub1).unwrap();
        handle_key_rotation(&mut state1, &rotation2, &dsa_pub2).unwrap();

        let audio = b"After rotation";
        let frame = encrypt_group_call_audio(&mut state1, audio).unwrap();
        let decrypted = decrypt_group_call_audio(&mut state2, &frame).unwrap();
        assert_eq!(decrypted, audio);
    }

    #[test]
    fn test_replay_attack_detection() {
        let dsa1 = DsaKeyPair::generate();
        let dsa_pub1 = dsa1.public.clone();
        let dsa2 = DsaKeyPair::generate();
        let dsa_pub2 = dsa2.public.clone();

        let id1 = ParticipantId::new();
        let id2 = ParticipantId::new();

        let (mut state1, announce) =
            create_group_call(id1.clone(), dsa_pub1.clone(), &dsa1).unwrap();

        let (mut state2, join) =
            join_group_call(&announce, id2.clone(), dsa_pub2.clone(), &dsa2).unwrap();

        let key_dist_1 = handle_participant_join(&mut state1, &join, &dsa1).unwrap();
        let key_dist_2 = distribute_sender_key_to_participant(
            &state2,
            &GroupCallParticipant {
                participant_id: id1.clone(),
                identity_public_key: dsa_pub1.clone(),
                ephemeral_kem_public: announce.ephemeral_kem_public.clone(),
                joined_at: announce.timestamp,
            },
            &dsa2,
        )
        .unwrap();
        handle_sender_key_distribution(&mut state2, &key_dist_1, &dsa_pub1).unwrap();
        handle_sender_key_distribution(&mut state1, &key_dist_2, &dsa_pub2).unwrap();

        let frame1 = encrypt_group_call_audio(&mut state1, b"frame 1").unwrap();
        let frame2 = encrypt_group_call_audio(&mut state1, b"frame 2").unwrap();

        decrypt_group_call_audio(&mut state2, &frame1).unwrap();
        decrypt_group_call_audio(&mut state2, &frame2).unwrap();

        let result = decrypt_group_call_audio(&mut state2, &frame1);
        assert!(matches!(result, Err(SdkError::ReplayAttack)));
    }

    #[test]
    fn test_max_participants() {
        let dsa = DsaKeyPair::generate();
        let dsa_pub = dsa.public.clone();
        let id = ParticipantId::new();

        let (mut state, _announce) = create_group_call(id.clone(), dsa_pub.clone(), &dsa).unwrap();

        for i in 0..(MAX_GROUP_CALL_PARTICIPANTS - 1) {
            let participant_id = ParticipantId::new();
            add_participant_from_existing(
                &mut state,
                participant_id,
                vec![i as u8; 32],
                vec![i as u8; 1665],
                0,
            )
            .unwrap();
        }

        assert_eq!(state.participant_count(), MAX_GROUP_CALL_PARTICIPANTS);
        assert!(!state.can_add_participant());

        let result = add_participant_from_existing(
            &mut state,
            ParticipantId::new(),
            vec![0; 32],
            vec![0; 1665],
            0,
        );
        assert!(matches!(result, Err(SdkError::GroupCallFull(_))));
    }
}
