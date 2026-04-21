//! Fault tolerance at larger committee size (slice 6.9, plan task 071).
//!
//! The plan targets "42/128 validators offline" — which would need a
//! cluster, not a laptop. The invariant being tested is simply that
//! Pyde tolerates up to f = floor((n-1)/3) offline validators and
//! keeps making progress. This test proves the invariant at N=7, f=2
//! (~28.6% offline) — a strict subset of a committee where quorum is
//! ceil(2n/3) = 5; with 2 down, 5 remain alive, quorum still holds.
//!
//! Slice 6.5 already proved 1/4. This extends to 2/7 — the smallest
//! multi-kill that stays under BFT's fault budget AND runs within the
//! harness's 8-validator cap.

mod common;

use common::TestNetwork;
use std::time::{Duration, Instant};

#[test]
#[ignore = "multi-node — subprocess-based, run via --ignored"]
fn two_of_seven_offline_keeps_chain_live() {
    let mut net = TestNetwork::spawn(7, true)
        .unwrap_or_else(|e| panic!("spawn 7v: {}", e));

    // Warm up to a healthy depth. 90s accommodates the contended-host
    // case where multiple multi-node binaries run in parallel.
    net.wait_for_slot(20, Duration::from_secs(90))
        .unwrap_or_else(|e| panic!("warm-up: {}", e));

    // Record the validators we're about to kill + the survivors.
    let funded = net
        .funded_addresses()
        .unwrap_or_else(|e| panic!("funded: {}", e));
    assert!(
        funded.len() >= 7,
        "expected >= 7 funded addresses, got {}",
        funded.len()
    );
    let killed_indices = [0usize, 1];
    let killed_addrs: Vec<[u8; 32]> = killed_indices.iter().map(|&i| funded[i]).collect();
    let survivors: Vec<usize> = (2..7).collect();

    let kill_slot = min_slot_over(&net, &survivors)
        .unwrap_or_else(|e| panic!("snapshot slot: {}", e));
    eprintln!(
        "killing {:?} at slot {} (survivors: {:?})",
        killed_indices, kill_slot, survivors
    );
    for &idx in &killed_indices {
        net.kill_node(idx)
            .unwrap_or_else(|e| panic!("kill node-{}: {}", idx, e));
    }

    // Survivors must advance by at least 10 slots post-kill. With 5
    // live validators and quorum = 5, this is tight: every live
    // validator MUST vote on every slot. 90s is plenty.
    let target_slot = kill_slot + 10;
    wait_for_slot_on_nodes(&net, &survivors, target_slot, Duration::from_secs(90))
        .unwrap_or_else(|e| {
            let dumps = per_node_dump(&net);
            panic!("{}\n{}", e, dumps);
        });

    // State roots must agree among the 5 survivors.
    let mut roots: Vec<(usize, String)> = Vec::new();
    for &i in &survivors {
        let r = net
            .state_root(i)
            .unwrap_or_else(|e| panic!("state_root node-{}: {}", i, e));
        roots.push((i, r));
    }
    let reference = roots[0].1.clone();
    for (i, r) in roots.iter().skip(1) {
        assert_eq!(
            r, &reference,
            "state_root divergence among survivors: node-{} = {}, node-{} = {}",
            roots[0].0, reference, i, r
        );
    }

    // No block in the post-kill window may name either killed
    // validator as proposer. Read headers from node-2 (first alive).
    let window_start = kill_slot + 3;
    let window_end = target_slot;
    let mut inspected = 0usize;
    for slot in window_start..=window_end {
        match net.proposer_of(survivors[0], slot) {
            Ok(Some(p)) => {
                inspected += 1;
                for (idx, killed) in killed_indices.iter().zip(killed_addrs.iter()) {
                    assert_ne!(
                        &p, killed,
                        "slot {} proposer is killed node-{} (0x{})",
                        slot,
                        idx,
                        hex::encode(p)
                    );
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("getBlockByNumber({}) failed: {}", slot, e),
        }
    }
    assert!(
        inspected >= 5,
        "expected >= 5 post-kill blocks, got {}",
        inspected
    );
    eprintln!(
        "verified {} post-kill blocks in slots {}..={} — no killed validators as proposer",
        inspected, window_start, window_end
    );
}

fn min_slot_over(net: &TestNetwork, indices: &[usize]) -> Result<u64, String> {
    let slots: Vec<u64> = net
        .current_slots()
        .into_iter()
        .filter(|(i, _)| indices.contains(i))
        .map(|(_, s)| s.ok_or_else(|| "missing slot on a node".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    slots.into_iter().min().ok_or_else(|| "empty indices".into())
}

fn wait_for_slot_on_nodes(
    net: &TestNetwork,
    indices: &[usize],
    target: u64,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let slots: Vec<(usize, Option<u64>)> = net
            .current_slots()
            .into_iter()
            .filter(|(i, _)| indices.contains(i))
            .collect();
        if slots
            .iter()
            .all(|(_, s)| s.map(|v| v >= target).unwrap_or(false))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "wait_for_slot_on_nodes({:?}, {}) timed out — {:?}",
                indices, target, slots
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn per_node_dump(net: &TestNetwork) -> String {
    net.nodes
        .iter()
        .map(|n| {
            format!(
                "\n=== node-{} ({}, rpc {}) ===\n{}",
                n.index,
                n.role,
                n.rpc_port,
                n.output_snapshot()
            )
        })
        .collect::<Vec<_>>()
        .join("")
}
