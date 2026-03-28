use std::fs;
use std::io;
use std::path::Path;

use cggmp24::{
    ExecutionId, PregeneratedPrimes, aux_info_gen, keygen, security_level::SecurityLevel128,
    signing::Presignature, supported_curves::Secp256k1,
};
use rand::rngs::OsRng;
use round_based::sim;

use ironsign::fifo_queue::FifoQueue;
// PresignaturePublicData does not derive Serialize/Deserialize,
// so we wrap "ppd" with our custom StoredPresignaturePublicData type.
use ironsign::ppd_serializer::StoredPresignaturePublicData;

type KeyShare = cggmp24::key_share::KeyShare<Secp256k1, SecurityLevel128>;

/// Runs AuxInfo + DKG for `n` parties, assembles complete key shares,
/// and persists them into `key_shares_dir/key_share_<i>.msgpack`.
fn generate_and_store_key_shares(n: u16, key_shares_dir: &Path) -> Vec<KeyShare> {
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

    // ── 4) Export key shares to shared folder ───────────────────────────
    fs::create_dir_all(key_shares_dir).expect("create key_shares directory");

    for i in 0..n as usize {
        let key_share_path = key_shares_dir.join(format!("key_share_{i}.msgpack"));
        let ks_bytes = rmp_serde::to_vec_named(&key_shares[i]).expect("serialize key_share");
        fs::write(&key_share_path, ks_bytes).expect("write key_share msgpack");

        println!(
            "[init] Node {i}: exported key_share to {}",
            key_share_path.display()
        );
    }

    println!(
        "[init] Key share initialization complete for {n} nodes in {}.",
        key_shares_dir.display()
    );
    key_shares
}

/// Counts files matching `key_share_*.msgpack` in `key_shares_dir`.
///
/// This is used as a fast sanity check before trying to deserialize each file.
fn key_share_file_count(key_shares_dir: &Path) -> usize {
    fs::read_dir(key_shares_dir)
        .expect("read key_shares directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("key_share_") && name.ends_with(".msgpack"))
                    .unwrap_or(false)
        })
        .count()
}

/// Loads exactly `n` key shares from `key_shares_dir` in index order.
///
/// Returns an error if the number of files does not match `n`, any expected
/// file is missing, or deserialization fails.
fn load_key_shares(n: u16, key_shares_dir: &Path) -> Result<Vec<KeyShare>, String> {
    let existing = key_share_file_count(key_shares_dir);
    if existing != n as usize {
        return Err(format!(
            "found {existing} key shares in {}, expected {n}",
            key_shares_dir.display()
        ));
    }

    let mut key_shares = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let key_share_path = key_shares_dir.join(format!("key_share_{i}.msgpack"));
        if !key_share_path.exists() {
            return Err(format!(
                "missing expected key share file {}",
                key_share_path.display()
            ));
        }

        let bytes = fs::read(&key_share_path)
            .map_err(|e| format!("failed reading {}: {e}", key_share_path.display()))?;
        let key_share: KeyShare = rmp_serde::from_slice(&bytes)
            .map_err(|e| format!("failed deserializing {}: {e}", key_share_path.display()))?;
        key_shares.push(key_share);
    }

    Ok(key_shares)
}

/// Initializes key shares for `n` nodes.
///
/// Reuses `output_dir/key_shares` when possible:
/// - If absent, generates and stores fresh key shares
/// - If present and count matches `n`, loads existing key shares
/// - If present but count mismatches `n` (or files are invalid), informs user, removes folder,
///   then regenerates key shares
fn initialize(n: u16, output_dir: &Path) -> Vec<KeyShare> {
    let key_shares_dir = output_dir.join("key_shares");

    if !key_shares_dir.exists() {
        println!("[init] No existing key_shares folder found. Generating fresh key shares...");
        return generate_and_store_key_shares(n, &key_shares_dir);
    }

    match load_key_shares(n, &key_shares_dir) {
        Ok(key_shares) => {
            println!(
                "[init] Loaded {} existing key shares from {}.",
                key_shares.len(),
                key_shares_dir.display()
            );
            key_shares
        }
        Err(reason) => {
            println!(
                "[init] Existing key shares cannot be reused ({reason}). Removing and regenerating..."
            );
            fs::remove_dir_all(&key_shares_dir).expect("remove stale key_shares folder");
            generate_and_store_key_shares(n, &key_shares_dir)
        }
    }
}

/// Exports the MPC shared public key in a portable form for external consumers.
///
/// Output:
/// - `public_key/shared_public_key.hex` (SEC1-compressed pubkey, hex-encoded)
fn export_shared_public_key(output_dir: &Path, key_shares: &[KeyShare]) {
    let public_key_dir = output_dir.join("public_key");
    fs::create_dir_all(&public_key_dir).expect("create public_key directory");

    let public_key_path = public_key_dir.join("shared_public_key.hex");
    let public_key_bytes = key_shares
        .first()
        .expect("at least one key share must exist")
        .shared_public_key
        .to_bytes(true);
    fs::write(
        &public_key_path,
        format!("{}\n", hex::encode(&public_key_bytes)),
    )
    .expect("write shared_public_key.hex");

    println!(
        "[init] Exported shared public key to {}",
        public_key_path.display()
    );
}

/// Generates and exports fresh presignatures for all `n` nodes.
///
/// Per-node output:
/// - `node_<i>/presig_pool.msgpack` (FIFO of private presignatures)
///
/// Node 0 output:
/// - `node_0/ppd_pool.msgpack` (FIFO of public presignature data)
fn regenerate_presignatures(n: u16, k: u16, output_dir: &Path, key_shares: &[KeyShare]) {
    let participants: Vec<u16> = (0..n).collect();

    // Each round of generate_presignature produces one presignature per party.
    // We run `k` rounds so every party accumulates `k` presignatures.
    let mut presig_pools: Vec<FifoQueue<Presignature<Secp256k1>>> = (0..n)
        .map(|_| FifoQueue::with_capacity(k as usize))
        .collect();
    let mut ppd_pool: FifoQueue<StoredPresignaturePublicData<Secp256k1>> =
        FifoQueue::with_capacity(k as usize);

    println!("[presig] Generating {k} presignatures for each of {n} nodes...");
    for j in 0..k {
        println!("[presig] Generating presignature set {}/{}...", j + 1, k);
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
            presig_pools[i].push(presig);
            if i == 0 {
                ppd_pool.push(StoredPresignaturePublicData { public });
            }
        }
    }

    for i in 0..n as usize {
        let node_dir = output_dir.join(format!("node_{i}"));
        fs::create_dir_all(&node_dir).expect("create node output directory");

        let presig_path = node_dir.join("presig_pool.msgpack");
        if presig_path.exists() {
            fs::remove_file(&presig_path).expect("delete old presig_pool.msgpack");
        }

        let presig_bytes = presig_pools[i].to_msgpack().expect("serialize presig_pool");
        fs::write(&presig_path, presig_bytes).expect("write presig_pool.msgpack");

        println!(
            "[presig] Node {i}: exported {k} fresh presignatures to {}",
            presig_path.display()
        );
    }

    let ppd_path = output_dir.join("node_0").join("ppd_pool.msgpack");
    if ppd_path.exists() {
        fs::remove_file(&ppd_path).expect("delete old ppd_pool.msgpack");
    }
    let ppd_bytes = ppd_pool.to_msgpack().expect("serialize ppd_pool");
    fs::write(&ppd_path, ppd_bytes).expect("write ppd_pool.msgpack");
    println!(
        "[presig] Exported shared public presignature data pool with {k} entries to {}",
        ppd_path.display()
    );

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
    export_shared_public_key(&output_dir, &key_shares);

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
