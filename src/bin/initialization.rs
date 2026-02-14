use std::fs;
use std::io;
use std::path::Path;

use cggmp24::{
    ExecutionId, PregeneratedPrimes, aux_info_gen, keygen, security_level::SecurityLevel128,
    supported_curves::Secp256k1,
};
use rand::rngs::OsRng;
use round_based::sim;

// PresignaturePublicData does not derive Serialize/Deserialize,
// so we wrap presignatures with our custom StoredPresignature type.
use ironsign::presig_storage::StoredPresignature;

/// Initializes the MPC system for `n` nodes with `k` pre-generated presignatures each.
///
/// For each node `i` (0 ..  n), serializes and writes to `<output_dir>/node_<i>/`:
///   - `aux_info.msgpack`    — auxiliary Paillier/Pedersen parameters
///   - `key_share.msgpack`   — complete ECDSA key share (includes aux info)
///   - `presig_pool.msgpack` — pool of `k` presignatures ready for offline signing
fn initialize(
    n: u16,
    output_dir: &Path,
) -> Vec<cggmp24::key_share::KeyShare<Secp256k1, SecurityLevel128>> {
    // ── 1) Auxiliary Information Generation ─────────────────────────────
    println!("[init] Generating auxiliary info...");
    let eid_aux = ExecutionId::new(b"init-aux");
    let aux = sim::run(n, |i, party| {
        let eid = eid_aux;
        async move {
            let mut rng = OsRng;
            let primes = PregeneratedPrimes::<SecurityLevel128>::generate(&mut rng);
            aux_info_gen(eid, i, n, primes).start(&mut rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // Serialize each node's aux_info before consuming it in KeyShare assembly
    let aux_serialized: Vec<Vec<u8>> = aux
        .iter()
        .map(|a| rmp_serde::to_vec(a).expect("serialize aux_info"))
        .collect();

    // ── 2) Distributed Key Generation ──────────────────────────────────
    println!("[init] Running DKG for {n} parties...");
    let eid_keygen = ExecutionId::new(b"init-keygen");
    let incomplete = sim::run(n, |i, party| {
        let eid = eid_keygen;
        async move {
            let mut rng = OsRng;
            keygen::<Secp256k1>(eid, i, n).start(&mut rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // ── 3) Assemble Complete Key Shares ────────────────────────────────
    let key_shares: Vec<_> = incomplete
        .into_iter()
        .zip(aux)
        .map(|(inc, a)| cggmp24::KeyShare::from_parts((inc, a)).expect("assemble key share"))
        .collect();

    // ── 4) Export Per-Node Static Data ──────────────────────────────────
    for i in 0..n as usize {
        let node_dir = output_dir.join(format!("node_{i}"));
        fs::create_dir_all(&node_dir).expect("create node output directory");

        // Aux info
        fs::write(node_dir.join("aux_info.msgpack"), &aux_serialized[i])
            .expect("write aux_info.msgpack");

        // Key share
        let ks_bytes = rmp_serde::to_vec_named(&key_shares[i]).expect("serialize key_share");
        fs::write(node_dir.join("key_share.msgpack"), ks_bytes).expect("write key_share.msgpack");

        println!(
            "[init] Node {i}: exported aux_info and key_share to {}",
            node_dir.display()
        );
    }

    println!("[init] Static initialization complete for {n} nodes.");
    key_shares
}

fn regenerate_presignatures(
    n: u16,
    k: u16,
    output_dir: &Path,
    key_shares: &[cggmp24::key_share::KeyShare<Secp256k1, SecurityLevel128>],
) {
    let participants: Vec<u16> = (0..n).collect();

    // Each round of generate_presignature produces one presignature per party.
    // We run k rounds so every party accumulates k presignatures.
    let mut presig_pools: Vec<Vec<StoredPresignature<Secp256k1>>> =
        (0..n).map(|_| Vec::with_capacity(k as usize)).collect();

    for j in 0..k {
        println!("[presig] Generating presignature {}/{}...", j + 1, k);
        let eid_bytes = format!("init-presig-{j}");
        let eid_presig = ExecutionId::new(eid_bytes.as_bytes());

        let presigs = sim::run(n, |i, party| {
            let eid = eid_presig;
            let key_share = key_shares[i as usize].clone();
            let participants = participants.clone();
            async move {
                let mut rng = OsRng;
                cggmp24::signing(eid, i, &participants, &key_share)
                    .generate_presignature(&mut rng, party)
                    .await
            }
        })
        .unwrap()
        .expect_ok()
        .into_vec();

        for (i, (presig, public)) in presigs.into_iter().enumerate() {
            presig_pools[i].push(StoredPresignature { presig, public });
        }
    }

    for i in 0..n as usize {
        let node_dir = output_dir.join(format!("node_{i}"));
        fs::create_dir_all(&node_dir).expect("create node output directory");

        let presig_path = node_dir.join("presig_pool.msgpack");
        if presig_path.exists() {
            fs::remove_file(&presig_path).expect("delete old presig_pool.msgpack");
        }

        let presig_bytes = rmp_serde::to_vec(&presig_pools[i]).expect("serialize presig_pool");
        fs::write(&presig_path, presig_bytes).expect("write presig_pool.msgpack");

        println!(
            "[presig] Node {i}: exported {k} fresh presignatures to {}",
            presig_path.display()
        );
    }

    println!("[presig] Regeneration complete.");
}

fn main() {
    let n: u16 = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(3);
    let k: u16 = std::env::args()
        .nth(2)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(5);
    let output_dir = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "./output".to_string());

    let output_dir = std::path::PathBuf::from(output_dir);
    let key_shares = initialize(n, &output_dir);

    regenerate_presignatures(n, k, &output_dir, &key_shares);

    loop {
        println!("[presig] Press ENTER to regenerate new presignatures...");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("read ENTER from stdin");

        regenerate_presignatures(n, k, &output_dir, &key_shares);
    }
}
