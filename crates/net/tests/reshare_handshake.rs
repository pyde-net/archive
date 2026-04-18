//! End-to-end integration test for the committee-resharing wire format.
//!
//! Spins up a real libp2p swarm carrying a gossipsub channel, pushes
//! `ResharingContribution`s through it wrapped in the same CBOR/length
//! framing the production node uses, and asserts the aggregation pipeline
//! converges on the invariant threshold public key. Closes the "no live
//! multi-node gossip test" caveat flagged on the task-034 PR.
//!
//! This is a single-process swarm — 1 gossip publisher, multiple
//! subscribers in the same swarm — but exercises the actual libp2p stack
//! end-to-end. Full cross-node scenarios are left to the multi-node E2E
//! slice.

use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    swarm::{NetworkBehaviour, SwarmEvent},
    Swarm, SwarmBuilder,
};
use pyde_crypto::threshold::{
    aggregate_new_share, canonical_resharing_subset, combine_shares,
    generate_decryption_share, generate_resharing_contribution, threshold_encrypt,
    threshold_keygen, ResharingContribution,
};
use std::time::Duration;
use tokio::time::timeout;

#[derive(NetworkBehaviour)]
struct GossipOnly {
    gossipsub: gossipsub::Behaviour,
}

fn build_swarm() -> Swarm<GossipOnly> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| {
            let cfg = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_millis(200))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .unwrap();
            let gossip = gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(key.clone()),
                cfg,
            )
            .unwrap();
            Ok(GossipOnly { gossipsub: gossip })
        })
        .unwrap()
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(30)))
        .build()
}

#[tokio::test]
async fn resharing_end_to_end_over_gossipsub() {
    // Old committee: 5 members, threshold 3. Generate keys + shares.
    const OLD_N: usize = 5;
    const OLD_T: usize = 3;
    const NEW_N: usize = 6;
    const NEW_T: usize = 4;
    const TARGET_EPOCH: u64 = 42;

    let (tpk, old_shares) = threshold_keygen(OLD_N, OLD_T).unwrap();
    let msg = b"cross-committee decrypt after rotation";
    let ct = threshold_encrypt(&tpk, msg).unwrap();

    // Two swarms: A publishes every contribution; B subscribes + collects.
    // Using two swarms over QUIC exercises the real transport path.
    let mut swarm_a = build_swarm();
    let mut swarm_b = build_swarm();
    let topic = IdentTopic::new("pyde/reshare/test");
    swarm_a.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    swarm_b.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

    swarm_a
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
        .unwrap();
    swarm_b
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
        .unwrap();

    // Wait for B's listen addr, then dial from A.
    let b_addr = loop {
        tokio::select! {
            ev = swarm_b.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = ev {
                    break address;
                }
            }
            _ = swarm_a.select_next_some() => {}
        }
    };
    let b_peer = *swarm_b.local_peer_id();
    let full_addr = b_addr.with(libp2p::multiaddr::Protocol::P2p(b_peer));
    swarm_a.dial(full_addr).unwrap();

    // Pre-build all resharing contributions from every old member.
    let contribs: Vec<ResharingContribution> = old_shares
        .iter()
        .map(|s| {
            generate_resharing_contribution(s, NEW_N, NEW_T, TARGET_EPOCH, b"gossip-test")
        })
        .collect();
    let mut to_publish: Vec<Vec<u8>> = contribs.iter().map(|c| c.to_bytes()).collect();

    // Collect bytes received on B.
    let mut received: Vec<ResharingContribution> = Vec::new();

    let driver = async {
        loop {
            if received.len() == contribs.len() {
                break;
            }
            tokio::select! {
                ev = swarm_a.select_next_some() => {
                    match ev {
                        SwarmEvent::Behaviour(GossipOnlyEvent::Gossipsub(
                            gossipsub::Event::Subscribed { peer_id: _, .. }
                        )) => {
                            // Gossipsub mesh is now ready between the two peers.
                            // Drain the queued contributions.
                            for bytes in to_publish.drain(..) {
                                // Retry on publish error (topic may still be
                                // bootstrapping heartbeats).
                                let mut attempt = 0;
                                while let Err(_) = swarm_a.behaviour_mut()
                                    .gossipsub.publish(topic.clone(), bytes.clone())
                                {
                                    attempt += 1;
                                    if attempt > 10 { break; }
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                ev = swarm_b.select_next_some() => {
                    if let SwarmEvent::Behaviour(GossipOnlyEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. }
                    )) = ev {
                        if let Some(c) = ResharingContribution::from_bytes(&message.data) {
                            // Dedup by from_old_index.
                            if !received.iter().any(|x| x.from_old_index == c.from_old_index) {
                                received.push(c);
                            }
                        }
                    }
                }
            }
        }
    };

    timeout(Duration::from_secs(10), driver)
        .await
        .expect("gossip round trip timed out");

    assert_eq!(received.len(), OLD_N);

    // On the receiving side, apply the canonical-subset rule and derive
    // new shares for each new member, mirroring what ValidatorEngine does
    // in production.
    let canonical = canonical_resharing_subset(&received, OLD_T).unwrap();
    let new_shares: Vec<_> = (1..=NEW_N)
        .map(|j| aggregate_new_share(j, &canonical).unwrap())
        .collect();

    // Threshold (4 of 6) new members decrypt the pre-rotation ciphertext.
    let dec: Vec<_> = new_shares[..NEW_T]
        .iter()
        .map(|s| generate_decryption_share(s, &ct))
        .collect();
    let plaintext = combine_shares(&dec, NEW_T, &ct).unwrap();
    assert_eq!(plaintext, msg);
}
