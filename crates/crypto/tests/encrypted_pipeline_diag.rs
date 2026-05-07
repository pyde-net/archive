//! Diagnostic: load real `threshold.pk` + every node's
//! `threshold.share` from a live testnet datadir, run the full
//! encrypt → share-gen → combine cycle against the loaded keys.
//!
//! Skipped unless `PYDE_DIAG_DATADIR` points at a testnet root.
//!
//! ```bash
//! PYDE_DIAG_DATADIR=/tmp/diag-net cargo test -p pyde-crypto \
//!   --test encrypted_pipeline_diag -- --nocapture
//! ```
//!
//! `quorum_for_committee` is duplicated from
//! `pyde-consensus::block` so we don't pull the entire workspace
//! into this fast diagnostic.

fn quorum_for_committee(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (2 * n).div_ceil(3)
}

#[test]
fn loaded_keys_round_trip() {
    let Ok(root) = std::env::var("PYDE_DIAG_DATADIR") else {
        eprintln!("skip: PYDE_DIAG_DATADIR not set");
        return;
    };
    let root = std::path::PathBuf::from(root);
    assert!(root.is_dir(), "{} must be a directory", root.display());

    let mut node_dirs: Vec<std::path::PathBuf> = std::fs::read_dir(&root)
        .expect("read datadir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("node-"))
                && p.join("threshold.pk").exists()
                && p.join("threshold.share").exists()
        })
        .collect();
    node_dirs.sort();
    assert!(
        !node_dirs.is_empty(),
        "no node-* dirs with threshold.{{pk,share}} under {}",
        root.display()
    );
    eprintln!("found {} node dirs", node_dirs.len());

    // 1. All threshold.pk files must be byte-identical.
    let pk_bytes_first = std::fs::read(node_dirs[0].join("threshold.pk")).unwrap();
    for d in &node_dirs[1..] {
        let pk_bytes = std::fs::read(d.join("threshold.pk")).unwrap();
        assert_eq!(
            pk_bytes_first,
            pk_bytes,
            "threshold.pk diverges at {}",
            d.display()
        );
    }

    let tpk = pyde_crypto::threshold::ThresholdPublicKey::from_bytes(&pk_bytes_first)
        .expect("parse threshold.pk");

    // 2. Load every share.
    let shares: Vec<pyde_crypto::threshold::KeyShare> = node_dirs
        .iter()
        .map(|d| {
            let bytes = std::fs::read(d.join("threshold.share")).unwrap();
            pyde_crypto::threshold::KeyShare::from_bytes(&bytes).expect("parse threshold.share")
        })
        .collect();

    for (i, ks) in shares.iter().enumerate() {
        eprintln!("  node-{}: share index = {} (1-based)", i, ks.index);
    }

    // Distinct indices?
    let mut idx: Vec<_> = shares.iter().map(|s| s.index).collect();
    idx.sort();
    let pre = idx.clone();
    idx.dedup();
    assert_eq!(idx, pre, "duplicate share indices: {:?}", pre);

    // 3. Encrypt with the on-disk public key.
    let payload = b"diag payload v1";
    let ct = pyde_crypto::threshold::threshold_encrypt(&tpk, payload).expect("encrypt");

    // 4. Wire round-trip.
    let ct_wire = ct.to_wire_bytes();
    let ct_rt = pyde_crypto::threshold::ThresholdCiphertext::from_wire_bytes(&ct_wire)
        .expect("wire round-trip");

    // 5. Decryption shares from each loaded share.
    let dec_shares: Vec<pyde_crypto::threshold::DecryptionShare> = shares
        .iter()
        .map(|ks| pyde_crypto::threshold::generate_decryption_share(ks, &ct_rt))
        .collect();

    let threshold = quorum_for_committee(node_dirs.len());
    eprintln!(
        "expected threshold for committee of {} = {}",
        node_dirs.len(),
        threshold
    );

    // 6. Try every threshold-sized subset.
    let n = dec_shares.len();
    let mut any_ok = false;
    let mut tried = 0usize;
    if threshold == 3 && n >= 3 {
        for i in 0..n {
            for j in (i + 1)..n {
                for k in (j + 1)..n {
                    tried += 1;
                    let subset = vec![
                        dec_shares[i].clone(),
                        dec_shares[j].clone(),
                        dec_shares[k].clone(),
                    ];
                    match pyde_crypto::threshold::combine_shares(&subset, threshold, &ct_rt) {
                        Ok(plain) => {
                            assert_eq!(plain, payload, "wrong plaintext");
                            eprintln!(
                                "  subset (idx {},{},{}) [shares {},{},{}] OK",
                                i, j, k, shares[i].index, shares[j].index, shares[k].index
                            );
                            any_ok = true;
                        }
                        Err(e) => {
                            eprintln!(
                                "  subset (idx {},{},{}) [shares {},{},{}] FAIL: {}",
                                i, j, k, shares[i].index, shares[j].index, shares[k].index, e
                            );
                        }
                    }
                }
            }
        }
    }

    eprintln!("\ntried {} subsets; any_ok={}", tried, any_ok);
    assert!(
        any_ok,
        "every threshold-sized subset of loaded shares FAILED to combine — \
         on-disk shares are not consistent with the on-disk public key. \
         This is the encrypted-tx pipeline bug."
    );
}
