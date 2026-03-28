use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cggmp24::{
    DataToSign, PrehashedDataToSign, signing::Presignature, supported_curves::Secp256k1,
};
use generic_ec::Scalar;

use ironsign::fifo_queue::FifoQueue;
use ironsign::ppd_serializer::StoredPresignaturePublicData;

/// Loads presignature and PPD pools from disk.
///
/// Expects:
///   - `<node_dir>/presig_pool.msgpack`
///   - `<node_dir>/ppd_pool.msgpack`
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

    // Load shared PPD pool from node_0 folder
    let ppd_path = node_dir.join("ppd_pool.msgpack");
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
    println!("[offline-node] Deleting pool files and folder after loading.");

    fs::remove_file(&presig_path).expect("delete presig_pool file after loading");
    fs::remove_file(&ppd_path).expect("delete ppd_pool file after loading");
    fs::remove_dir(node_dir).expect("delete node directory after loading pools");

    (presig_pool, ppd_pool)
}

fn main() {
    let prehashed = std::env::args().any(|a| a == "--prehashed");

    let input_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./output".to_string()); // TODO: to input
    let output_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "./output".to_string());

    let input_dir = PathBuf::from(input_dir);
    let output_dir = PathBuf::from(output_dir);

    let input_node_dir = input_dir.join("node_0");
    let output_node_dir = output_dir.join("node_0");

    println!(
        "[offline-node] Initializing offline node from input {} and output set to {}...",
        input_node_dir.display(),
        output_dir.display()
    );

    fs::create_dir_all(&output_node_dir).expect("create output node_0 directory");

    let (mut presig_pool, mut ppd_pool) = load_pools(&input_node_dir);

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

            let (new_presig, new_ppd) = load_pools(&input_node_dir);
            presig_pool = new_presig;
            ppd_pool = new_ppd;
            continue;
        }

        // ── Wait for payload ───────────────────────────────────────────
        println!(
            "[offline-node] Waiting for payload to sign ({} presignatures remaining).",
            presig_pool.len()
        );
        println!(
            "[offline-node] Enter payload file name from input folder {}:",
            input_dir.display()
        );

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("read payload path from stdin");
        let payload_name = input.trim();

        if payload_name.is_empty() {
            eprintln!("[offline-node] Error: no payload file name provided. Try again.");
            continue;
        }

        let payload_file = input_dir.join(payload_name);
        if !payload_file.exists() {
            eprintln!(
                "[offline-node] Error: payload file '{}' not found. Try again.",
                payload_file.display()
            );
            continue;
        }

        // ── Read raw payload bytes ─────────────────────────────────────
        let payload_bytes = fs::read(&payload_file).expect("read payload file");
        println!(
            "[offline-node] Read {} bytes from payload.",
            payload_bytes.len()
        );

        // ── Create message to sign ─────────────────────────────────────
        let msg = if prehashed {
            // Payload is already a hash (e.g. Bitcoin sighash) – use as-is.
            let scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(&payload_bytes);
            PrehashedDataToSign::from_scalar(scalar).insecure_assume_preimage_known()
        } else {
            DataToSign::digest::<sha2::Sha256>(&payload_bytes)
        };

        // ── Pop presignature and PPD from pools ────────────────────────
        let presig = presig_pool
            .pop_next()
            .expect("presig pool unexpectedly empty");
        let ppd = ppd_pool.pop_next().expect("ppd pool unexpectedly empty");

        // ── Issue partial signature ────────────────────────────────────
        let partial_signature = presig.issue_partial_signature(msg);

        // Ensure output node directory exists even if it was removed externally.
        fs::create_dir_all(&output_node_dir).expect("recreate output node_0 directory");

        // ── Serialize and export partial signature + PPD as separate files ─
        let partial_sig_filename = format!("offline_partial_sig_{sig_counter}.msgpack");
        let partial_sig_path = output_node_dir.join(&partial_sig_filename);
        let partial_sig_bytes =
            rmp_serde::to_vec(&partial_signature).expect("serialize partial signature");
        fs::write(&partial_sig_path, partial_sig_bytes).expect("write partial signature file");

        let ppd_filename = format!("ppd_{sig_counter}.msgpack");
        let ppd_path = output_node_dir.join(&ppd_filename);
        let ppd_bytes = rmp_serde::to_vec(&ppd).expect("serialize ppd");
        fs::write(&ppd_path, ppd_bytes).expect("write ppd file");

        // ── Delete payload file ────────────────────────────────────────
        fs::remove_file(&payload_file).expect("delete payload file");

        sig_counter += 1;
        println!(
            "[offline-node] Success! Partial signature exported to {}, PPD exported to {}. Payload file deleted.",
            partial_sig_path.display(),
            ppd_path.display()
        );
    }
}
