use super::*;
use crate::crypto::keys::DsaKeyPair;

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

    let screen_data = b"Screenshare frame data";
    let screen_frame = encrypt_group_call_screenshare(&mut initiator_state, screen_data).unwrap();
    let decrypted_screen =
        decrypt_group_call_screenshare(&mut joiner_state, &screen_frame).unwrap();
    assert_eq!(decrypted_screen, screen_data);
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

    let (mut state1, announce) = create_group_call(id1.clone(), dsa_pub1.clone(), &dsa1).unwrap();

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

    let (mut state1, announce) = create_group_call(id1.clone(), dsa_pub1.clone(), &dsa1).unwrap();

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
    assert!(matches!(result, Err(crate::error::SdkError::ReplayAttack)));
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
    assert!(matches!(
        result,
        Err(crate::error::SdkError::GroupCallFull(_))
    ));
}
