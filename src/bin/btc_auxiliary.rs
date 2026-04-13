//! Bitcoin Auxiliary Layer
//!
//! Proves MPC/TSS signing correctness on Bitcoin regtest:
//! 1. Connects to regtest via RPC
//! 2. Derives SegWit address B from MPC shared public key
//! 3. Funds B from mining wallet
//! 4. Builds unsigned SegWit tx: B → C
//! 5. Extracts sighash payload, writes to MPC input folder
//! 6. Waits for MPC signature from output folder
//! 7. Injects signature into tx, broadcasts to regtest
//! 8. Mines blocks, verifies transfer

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::consensus::encode as btc_encode;
use bitcoin::hashes::Hash;
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::{self, Secp256k1 as BtcSecp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Address, Amount, Network, Sequence, Witness};

use bitcoincore_rpc::{Auth, Client, RpcApi};

use cggmp24::signing::Signature;
use cggmp24::supported_curves::Secp256k1 as MpcSecp256k1;

/// Connects to Bitcoin Core regtest via JSON-RPC.
fn connect_rpc() -> Client {
    Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass("ironsign".to_string(), "ironsign123".to_string()),
    )
    .expect("connect to bitcoin regtest RPC")
}

/// Loads MPC shared public key from `public_key/shared_public_key.hex`.
fn load_mpc_public_key(public_key_dir: &Path) -> CompressedPublicKey {
    let public_key_path = public_key_dir.join("shared_public_key.hex");
    let hex_str = fs::read_to_string(&public_key_path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", public_key_path.as_path().display()));

    let pk_bytes = hex::decode(hex_str.trim()).unwrap_or_else(|e| {
        panic!(
            "invalid hex in {}: {e}",
            public_key_path.as_path().display()
        )
    });

    CompressedPublicKey::from_slice(&pk_bytes).unwrap_or_else(|e| {
        panic!(
            "parse compressed public key from {} failed: {e}",
            public_key_path.as_path().display()
        )
    })
}

/// Derives a P2WPKH (SegWit v0) address from the MPC shared public key.
fn derive_address_b(pubkey: &CompressedPublicKey) -> Address {
    Address::p2wpkh(pubkey, Network::Regtest)
}

/// Creates a random address C for the receiving end of the proof tx.
fn generate_address_c() -> Address {
    let secp = BtcSecp256k1::new();
    let (_, pk) = secp.generate_keypair(&mut rand::thread_rng());
    let compressed = CompressedPublicKey(pk);
    Address::p2wpkh(&compressed, Network::Regtest)
}

/// Mines `count` blocks to `address`, returns block hashes.
fn mine_blocks(rpc: &Client, count: u64, address: &Address) -> Vec<bitcoin::BlockHash> {
    rpc.generate_to_address(count, address)
        .expect("mine blocks")
}

/// Waits for user to press ENTER with a prompt.
#[allow(dead_code)]
fn wait_enter(prompt: &str) {
    println!("{prompt}");
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).expect("read stdin");
}

/// Reads a line from stdin after printing a prompt.
fn read_line(prompt: &str) -> String {
    println!("{prompt}");
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).expect("read stdin");
    buf.trim().to_string()
}

fn main() {
    let mpc_input_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./output".to_string()); // TODO: to input
    let mpc_output_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "./output".to_string());

    let mpc_output_dir_path = PathBuf::from(&mpc_output_dir);
    let mpc_input_dir_path = PathBuf::from(&mpc_input_dir);
    fs::create_dir_all(&mpc_input_dir_path).expect("create MPC input dir");

    // ── 1. Connect to regtest ──────────────────────────────────────────
    println!("[btc] Connecting to Bitcoin regtest...");
    let rpc = connect_rpc();
    let info = rpc.get_blockchain_info().expect("get blockchain info");
    println!(
        "[btc] Connected. Chain: {}, Blocks: {}",
        info.chain, info.blocks
    );

    // ── 2. Load MPC public key and derive address B ────────────────────
    let public_key_dir = mpc_input_dir_path.join("public_key");
    println!(
        "[btc] Loading MPC shared public key from {}...",
        public_key_dir.display()
    );
    let mpc_pubkey = load_mpc_public_key(&public_key_dir);
    let address_b = derive_address_b(&mpc_pubkey);
    println!("[btc] MPC public key: {}", mpc_pubkey);
    println!("[btc] Address B (P2WPKH): {}", address_b);

    // ── 3. Create mining wallet and address A ──────────────────────────
    println!("[btc] Setting up mining wallet...");
    let _ = rpc.create_wallet("miner", None, None, None, None);
    let address_a = rpc
        .get_new_address(Some("miner"), None)
        .expect("get new mining address")
        .require_network(Network::Regtest)
        .expect("regtest address");
    println!("[btc] Address A (miner): {}", address_a);

    // Mine 101 blocks so coinbase is spendable
    println!("[btc] Mining 101 blocks to address A...");
    mine_blocks(&rpc, 101, &address_a);

    // ── 4. Fund address B ──────────────────────────────────────────────
    let fund_amount = Amount::from_btc(2.0).unwrap(); //TODO: zistit jak tento funding funguje, pretoez tu nikde nefiguruje address_a.
    println!("[btc] Sending {} to address B...", fund_amount);
    let fund_txid = rpc
        .send_to_address(&address_b, fund_amount, None, None, None, None, None, None)
        .expect("send to address B");
    println!("[btc] Funding tx: {fund_txid}");

    // Mine 1 block to confirm the funding tx
    mine_blocks(&rpc, 1, &address_a);

    // ── 5. Find the UTXO at address B ──────────────────────────────────
    let fund_tx = rpc
        .get_raw_transaction(&fund_txid, None)
        .expect("get funding tx");
    let (vout_index, utxo_value) = fund_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, txout)| txout.script_pubkey == address_b.script_pubkey())
        .map(|(idx, txout)| (idx as u32, txout.value))
        .expect("find UTXO for address B in funding tx");

    println!(
        "[btc] Found UTXO: txid={fund_txid}, vout={vout_index}, value={}",
        utxo_value
    );

    // ── 6. Generate address C ──────────────────────────────────────────
    let address_c = generate_address_c();
    println!("[btc] Address C (destination): {}", address_c);

    // ── 7. Build unsigned SegWit transaction B → C ─────────────────────
    let send_amount = Amount::from_btc(1.0).unwrap();
    let fee = Amount::from_sat(1000);
    let change_amount = utxo_value - send_amount - fee;

    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: fund_txid,
                vout: vout_index,
            },
            script_sig: ScriptBuf::new(), // empty for SegWit
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: send_amount,
                script_pubkey: address_c.script_pubkey(),
            },
            TxOut {
                value: change_amount,
                script_pubkey: address_b.script_pubkey(), // change back to B
            },
        ],
    };

    // ── 8. Compute sighash (BIP-143 for P2WPKH) ───────────────────────
    let script_code = ScriptBuf::new_p2wpkh(&mpc_pubkey.wpubkey_hash());
    let mut sighash_cache = SighashCache::new(&unsigned_tx);
    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            0, // input index
            &script_code,
            utxo_value,
            EcdsaSighashType::All,
        )
        .expect("compute sighash");

    let sighash_bytes = sighash.to_byte_array();
    println!("[btc] Sighash (hex): {}", hex::encode(&sighash_bytes));

    // ── 9. Write sighash as payload for MPC system ─────────────────────
    let payload_filename = "btc_sighash_payload.bin";
    let payload_path = mpc_input_dir_path.join(payload_filename);
    fs::write(&payload_path, &sighash_bytes).expect("write sighash payload");
    println!(
        "[btc] Sighash payload written to {}",
        payload_path.display()
    );

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Now run coord_runtime and offline_node to sign the          ║");
    println!(
        "║  payload file: {}                       ║",
        payload_filename
    );
    println!("║                                                              ║");
    println!("║  Once the signature is exported, press ENTER here.           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let sig_filename = read_line(
        "[btc] Enter the signature filename from MPC output (e.g. signatures/signature_0.msgpack):",
    );
    let sig_path = mpc_output_dir_path.join(&sig_filename);

    // ── 10. Load MPC signature ─────────────────────────────────────────
    let sig_bytes = fs::read(&sig_path).expect("read MPC signature file");
    let mpc_sig: Signature<MpcSecp256k1> =
        rmp_serde::from_slice(&sig_bytes).expect("deserialize MPC signature");

    println!(
        "[btc] MPC signature loaded: r={:?}, s={:?}",
        mpc_sig.r, mpc_sig.s
    );

    // ── 11. Convert MPC signature to bitcoin DER + sighash type ────────
    // Extract r and s as 32-byte big-endian arrays from the MPC Signature.
    let r_bytes = mpc_sig.r.to_be_bytes();
    let s_bytes = mpc_sig.s.to_be_bytes();

    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&r_bytes);
    compact[32..].copy_from_slice(&s_bytes);

    let btc_sig = bitcoin::ecdsa::Signature {
        signature: secp256k1::ecdsa::Signature::from_compact(&compact)
            .expect("construct secp256k1 signature from r||s"),
        sighash_type: EcdsaSighashType::All,
    };

    // ── 12. Inject witness into the transaction ────────────────────────
    let mut signed_tx = unsigned_tx;
    signed_tx.input[0].witness = Witness::p2wpkh(&btc_sig, &mpc_pubkey.0);

    let raw_tx = btc_encode::serialize_hex(&signed_tx);
    println!("[btc] Signed transaction (hex): {}", &raw_tx[..80]);
    println!("      ... ({} total hex chars)", raw_tx.len());

    // ── 13. Broadcast transaction ──────────────────────────────────────
    let txid = rpc
        .send_raw_transaction(&signed_tx)
        .expect("broadcast signed transaction");
    println!("[btc] Transaction broadcast! txid = {txid}");

    // ── 14. Mine blocks to confirm ─────────────────────────────────────
    mine_blocks(&rpc, 6, &address_a);
    println!("[btc] Mined 6 confirmation blocks.");

    // ── 15. Verify ─────────────────────────────────────────────────────
    let confirmed_tx = rpc
        .get_raw_transaction_info(&txid, None)
        .expect("get confirmed tx info");
    println!(
        "[btc] Transaction confirmed in block: {:?}",
        confirmed_tx.blockhash
    );
    println!("[btc] Confirmations: {:?}", confirmed_tx.confirmations);

    println!();
    println!("╔════════════════════════════════════════════════════════════════════════╗");
    println!("║  SUCCESS: 1 BTC sent from address B to address C                       ║");
    println!("║                                                                        ║");
    println!("║  B = {} (MPC-controlled)     ║", address_b);
    println!("║  C = {} (random destination) ║", address_c);
    println!("║                                                                        ║");
    println!("║  This proves the MPC/TSS system controls the private key               ║");
    println!("║  for address B and can produce valid Bitcoin signatures.               ║");
    println!("╚════════════════════════════════════════════════════════════════════════╝");
}
