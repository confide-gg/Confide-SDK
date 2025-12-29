use crate::error::{Result, SdkError};

use super::crypto::{decrypt_with_nonce, encrypt_with_nonce};
use super::messages::GroupCallMediaFrame;
use super::state::GroupCallState;
use super::types::MediaType;

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

pub fn encrypt_group_call_screenshare(
    state: &mut GroupCallState,
    plaintext: &[u8],
) -> Result<GroupCallMediaFrame> {
    encrypt_media_frame(state, plaintext, MediaType::Screenshare)
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

pub fn decrypt_group_call_screenshare(
    state: &mut GroupCallState,
    frame: &GroupCallMediaFrame,
) -> Result<Vec<u8>> {
    if frame.media_type != MediaType::Screenshare {
        return Err(SdkError::GroupCall(
            "Expected screenshare frame".to_string(),
        ));
    }
    decrypt_media_frame(state, frame)
}

fn encrypt_media_frame(
    state: &mut GroupCallState,
    plaintext: &[u8],
    media_type: MediaType,
) -> Result<GroupCallMediaFrame> {
    let counter = match media_type {
        MediaType::Audio => &mut state.our_sender_key_state.audio_nonce_counter,
        MediaType::Video => &mut state.our_sender_key_state.video_nonce_counter,
        MediaType::Screenshare => &mut state.our_sender_key_state.screenshare_nonce_counter,
    };

    let mut nonce = [0u8; 12];
    nonce[0] = media_type.nonce_prefix();
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

    let expected_counter = match frame.media_type {
        MediaType::Audio => &mut recv_key.audio_nonce_counter,
        MediaType::Video => &mut recv_key.video_nonce_counter,
        MediaType::Screenshare => &mut recv_key.screenshare_nonce_counter,
    };

    if frame.nonce_counter < *expected_counter {
        return Err(SdkError::ReplayAttack);
    }

    let mut nonce = [0u8; 12];
    nonce[0] = frame.media_type.nonce_prefix();
    nonce[4..].copy_from_slice(&frame.nonce_counter.to_be_bytes());

    let plaintext = decrypt_with_nonce(&recv_key.key, &nonce, &frame.ciphertext)?;

    *expected_counter = frame.nonce_counter + 1;

    Ok(plaintext)
}
