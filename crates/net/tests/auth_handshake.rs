//! End-to-end integration test for the FALCON peer-auth protocol.
//!
//! Stands up two real libp2p swarms carrying only the `PydeAuth`
//! request-response behaviour (a slim subset of `PydeBehaviour`, to keep
//! the test focused on the auth wire format). One swarm dials the other,
//! initiates a `PydeAuthReq`, the responder signs an attestation, and
//! the initiator runs `apply_auth_response` to drive the full state
//! transition — same path as production. This closes the
//! "pure-function-only" testing gap flagged in the auth unit tests.

use futures::StreamExt;
use libp2p::{
    request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    Swarm, SwarmBuilder,
};
use pyde_account::address::derive_eoa_address;
use pyde_crypto::falcon::falcon_keygen;
use pyde_net::auth::{
    apply_auth_response, auth_behaviour, build_auth_resp, generate_nonce, AuthOutcome, PydeAuthReq,
    PydeAuthResp,
};
use pyde_net::peer::{Direction, PeerInfo, PeerManager, PeerRole};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;

#[derive(NetworkBehaviour)]
struct AuthOnly {
    auth: request_response::cbor::Behaviour<PydeAuthReq, PydeAuthResp>,
}

fn build_swarm() -> Swarm<AuthOnly> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| AuthOnly {
            auth: auth_behaviour(),
        })
        .expect("behaviour ok")
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(30)))
        .build()
}

/// Drive both swarms' event loops until the initiator records an
/// `AuthOutcome`, returning the outcome and final peer-manager state.
/// Times out on failure so test suites don't hang.
async fn run_handshake(
    mut initiator: Swarm<AuthOnly>,
    mut responder: Swarm<AuthOnly>,
    responder_pubkey: Vec<u8>,
    responder_sk: pyde_crypto::falcon::FalconSecretKey,
    responder_pk: pyde_crypto::falcon::FalconPublicKey,
    committee_keys: Vec<Vec<u8>>,
) -> (AuthOutcome, PeerManager, Vec<u8>) {
    // Both sides listen on a random loopback port.
    initiator
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
        .unwrap();
    responder
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
        .unwrap();

    // Pump until both have concrete listen addrs, then have A dial B.
    let responder_addr = loop {
        tokio::select! {
            event = responder.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    break address;
                }
            }
            _ = initiator.select_next_some() => {}
        }
    };
    let responder_peer_id = *responder.local_peer_id();
    let full_addr = responder_addr.with(libp2p::multiaddr::Protocol::P2p(responder_peer_id));
    initiator.dial(full_addr).unwrap();

    // Track initiator state.
    let mut nonces: HashMap<libp2p::PeerId, [u8; 32]> = HashMap::new();
    let mut peer_manager = PeerManager::new(10, 10, 10, 100);
    let mut connected_peer: Option<libp2p::PeerId> = None;
    let mut sent_request = false;
    let mut outcome: Option<AuthOutcome> = None;

    // 5-second test budget. Handshake typically completes in <200ms over
    // loopback; this is defense against CI flakiness.
    let driver = async {
        loop {
            if outcome.is_some() {
                break;
            }
            tokio::select! {
                ev = initiator.select_next_some() => {
                    match ev {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            peer_manager.add_peer(PeerInfo::new(peer_id, Direction::Outbound));
                            connected_peer = Some(peer_id);
                        }
                        SwarmEvent::Behaviour(AuthOnlyEvent::Auth(
                            request_response::Event::Message {
                                message: request_response::Message::Response { response, .. },
                                peer,
                            },
                        )) => {
                            outcome = Some(apply_auth_response(
                                peer,
                                &response,
                                &mut nonces,
                                &mut peer_manager,
                                &committee_keys,
                            ));
                        }
                        _ => {}
                    }
                }
                ev = responder.select_next_some() => {
                    if let SwarmEvent::Behaviour(AuthOnlyEvent::Auth(
                        request_response::Event::Message {
                            message: request_response::Message::Request { request, channel, .. },
                            ..
                        },
                    )) = ev {
                        let eoa = derive_eoa_address(&responder_pubkey);
                        let resp = build_auth_resp(&request, &eoa, &responder_sk, &responder_pk).unwrap();
                        let _ = responder.behaviour_mut().auth.send_response(channel, resp);
                    }
                }
            }
            // Fire the outbound request once the initiator is connected.
            if !sent_request {
                if let Some(peer) = connected_peer {
                    let nonce = generate_nonce();
                    nonces.insert(peer, nonce);
                    initiator
                        .behaviour_mut()
                        .auth
                        .send_request(&peer, PydeAuthReq { nonce });
                    sent_request = true;
                }
            }
        }
    };

    timeout(Duration::from_secs(5), driver)
        .await
        .expect("handshake timed out");

    (outcome.unwrap(), peer_manager, responder_pubkey)
}

#[tokio::test]
async fn end_to_end_handshake_with_committee_member() {
    // Responder holds a FALCON key that's in the committee list — initiator
    // should end up recording the attestation AND promoting the peer to
    // validator.
    let (pk, sk) = falcon_keygen().unwrap();
    let pk_bytes = pk.as_bytes().to_vec();
    let committee = vec![pk_bytes.clone()];

    let initiator = build_swarm();
    let responder = build_swarm();
    let (outcome, mgr, expected_pk) =
        run_handshake(initiator, responder, pk_bytes, sk, pk, committee).await;

    assert_eq!(outcome, AuthOutcome::StoredAsValidator);
    // Exactly one peer tracked by the initiator — the responder.
    let peer_id = mgr.all_peers().next().map(|p| p.peer_id).unwrap();
    assert_eq!(
        mgr.peer_falcon_pubkey(&peer_id),
        Some(expected_pk.as_slice())
    );
    assert_eq!(mgr.get_peer(&peer_id).unwrap().role, PeerRole::Validator);
}

#[tokio::test]
async fn end_to_end_handshake_with_non_committee_peer() {
    // Responder is NOT in the committee — attestation should land but role
    // stays Unknown. Consensus-topic filter on the node side would then
    // drop consensus messages from this peer.
    let (pk, sk) = falcon_keygen().unwrap();
    let pk_bytes = pk.as_bytes().to_vec();
    let committee: Vec<Vec<u8>> = vec![]; // empty committee

    let initiator = build_swarm();
    let responder = build_swarm();
    let (outcome, mgr, expected_pk) =
        run_handshake(initiator, responder, pk_bytes, sk, pk, committee).await;

    assert_eq!(outcome, AuthOutcome::StoredAsNonValidator);
    let peer_id = mgr.all_peers().next().map(|p| p.peer_id).unwrap();
    assert_eq!(
        mgr.peer_falcon_pubkey(&peer_id),
        Some(expected_pk.as_slice())
    );
    assert_eq!(mgr.get_peer(&peer_id).unwrap().role, PeerRole::Unknown);
}
