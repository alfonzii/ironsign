use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cggmp24::{DataToSign, signing::Presignature, supported_curves::Secp256k1};

use ironsign::fifo_queue::FifoQueue;
use ironsign::ppd_serializer::StoredPresignaturePublicData;

/// Loads presignature and PPD pools from disk.
///
/// Expects:
///   - `<node_dir>/presig_pool.msgpack`
///   - `<node_dir>/../ppd_pool.msgpack`  (shared, one level above node dir)
///
/// Asserts both pools have equal length.
fn load_pools(
    node_dir: &Path,
) -> (
    FifoQueue<Presignature<Secp256k1>>,
    FifoQueue<StoredPresignaturePublicData<Secp256k1>>,
) {
    // Load per-node presignature pool
    let presig_path = node_dir.join("presig_pool.msgpack");
    let presig_bytes = fs::read(&presig_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", presig_path.display()));
    let presig_pool: FifoQueue<Presignature<Secp256k1>> =
        FifoQueue::from_msgpack(&presig_bytes).expect("deserialize presig_pool");

    // Load shared PPD pool (one level up from node_dir)
    let ppd_path = node_dir
        .parent()
        .expect("node_dir must have a parent directory")
        .join("ppd_pool.msgpack");
    let ppd_bytes = fs::read(&ppd_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", ppd_path.display()));
    let ppd_pool: FifoQueue<StoredPresignaturePublicData<Secp256k1>> =
        FifoQueue::from_msgpack(&ppd_bytes).expect("deserialize ppd_pool");

    assert_eq!(
        presig_pool.len(),
        ppd_pool.len(),
        "presig pool ({}) and ppd pool ({}) must have the same size",
        presig_pool.len(),
        ppd_pool.len()
    );

    println!(
        "[offline-node] Loaded {} presignatures and {} PPDs.",
        presig_pool.len(),
        ppd_pool.len()
    );

    fs::remove_file(&presig_path).expect("delete presig_pool file after loading");
    fs::remove_file(&ppd_path).expect("delete ppd_pool file after loading");

    (presig_pool, ppd_pool)
}

fn main() {
    let node_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./output/node_0".to_string()); // TODO: delete output, because it is assumed to run independently
    let node_dir = PathBuf::from(node_dir);

    println!(
        "[offline-node] Initializing offline node from {}...",
        node_dir.display()
    );

    let (mut presig_pool, mut ppd_pool) = load_pools(&node_dir);

    let mut sig_counter: u64 = 0;

    loop {
        // ── Check if pools are exhausted ───────────────────────────────
        if presig_pool.is_empty() {
            println!(
                "[offline-node] Presignature pool exhausted! \
                 Please regenerate presignatures (run initialization) \
                 and press ENTER to reload..."
            );
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .expect("read ENTER from stdin");

            let (new_presig, new_ppd) = load_pools(&node_dir);
            presig_pool = new_presig;
            ppd_pool = new_ppd;
            continue;
        }

        // ── Wait for payload ───────────────────────────────────────────
        println!(
            "[offline-node] Waiting for payload to sign ({} presignatures remaining).",
            presig_pool.len()
        );
        println!("[offline-node] Enter path to payload file:");

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("read payload path from stdin");
        let payload_path = input.trim();

        if payload_path.is_empty() {
            eprintln!("[offline-node] Error: no payload path provided. Try again.");
            continue;
        }

        let payload_file = Path::new(payload_path);
        if !payload_file.exists() {
            eprintln!(
                "[offline-node] Error: payload file '{}' not found. Try again.",
                payload_path
            );
            continue;
        }

        // ── Read raw payload bytes ─────────────────────────────────────
        let payload_bytes = fs::read(payload_file).expect("read payload file");
        println!(
            "[offline-node] Read {} bytes from payload.",
            payload_bytes.len()
        );

        // ── Create message to sign ─────────────────────────────────────
        let msg = DataToSign::digest::<sha2::Sha256>(&payload_bytes);

        // ── Pop presignature and PPD from pools ────────────────────────
        let presig = presig_pool
            .pop_next()
            .expect("presig pool unexpectedly empty");
        let ppd = ppd_pool.pop_next().expect("ppd pool unexpectedly empty");

        // ── Issue partial signature ────────────────────────────────────
        let partial_signature = presig.issue_partial_signature(msg);

        // ── Serialize and export partial signature + PPD as separate files ─
        let partial_sig_filename = format!("partial_sig_{sig_counter}.msgpack"); // TODO: urovnat nazvy partial signatures (pozriet ako ma coord runtime)
        let partial_sig_path = node_dir.join(&partial_sig_filename);
        let partial_sig_bytes =
            rmp_serde::to_vec(&partial_signature).expect("serialize partial signature");
        fs::write(&partial_sig_path, partial_sig_bytes).expect("write partial signature file");

        let ppd_filename = format!("ppd_{sig_counter}.msgpack");
        let ppd_path = node_dir.join(&ppd_filename);
        let ppd_bytes = rmp_serde::to_vec(&ppd).expect("serialize ppd");
        fs::write(&ppd_path, ppd_bytes).expect("write ppd file");

        // ── Delete payload file ────────────────────────────────────────
        fs::remove_file(payload_file).expect("delete payload file");

        sig_counter += 1;
        println!(
            "[offline-node] Success! Partial signature exported to {}, PPD exported to {}. Payload file deleted.",
            partial_sig_path.display(),
            ppd_path.display()
        );
    }
}
