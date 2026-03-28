use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cggmp24::{
    DataToSign, PartialSignature, PrehashedDataToSign,
    signing::{Presignature, Signature},
    supported_curves::Secp256k1,
};
use generic_ec::Scalar;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, sleep};

use ironsign::fifo_queue::FifoQueue;
use ironsign::ppd_serializer::StoredPresignaturePublicData;

type NodeResult<T> = Result<T, String>;

enum NodeCommand {
    Init {
        reply: oneshot::Sender<NodeResult<usize>>,
    },
    Sign {
        payload: Vec<u8>,
        reply: oneshot::Sender<NodeResult<PartialSignature<Secp256k1>>>,
    },
}

#[derive(Clone)]
struct NodeHandle {
    node_id: u16,
    tx: mpsc::UnboundedSender<NodeCommand>,
}

/// Loads a node's presignature pool from `node_dir/presig_pool.msgpack`,
/// then removes the consumed pool file and the now-empty `node_dir`.
fn load_presig_pool(node_dir: &Path) -> NodeResult<FifoQueue<Presignature<Secp256k1>>> {
    let presig_path = node_dir.join("presig_pool.msgpack");
    let bytes = fs::read(&presig_path)
        .map_err(|e| format!("read {} failed: {e}", presig_path.display()))?;
    let pool = FifoQueue::from_msgpack(&bytes)
        .map_err(|e| format!("deserialize {} failed: {e}", presig_path.display()))?;

    fs::remove_file(&presig_path)
        .map_err(|e| format!("delete {} failed: {e}", presig_path.display()))?;
    fs::remove_dir(node_dir).map_err(|e| format!("delete {} failed: {e}", node_dir.display()))?;

    Ok(pool)
}

/// Spawns one online MPC node task.
///
/// The task accepts coordinator commands via channel:
/// - `Init`: loads presignature pool from `input_dir/node_<id>`
/// - `Sign`: pops one presignature and returns a partial signature for payload
fn spawn_online_node(node_id: u16, input_dir: PathBuf, prehashed: bool) -> NodeHandle {
    let (tx, mut rx) = mpsc::unbounded_channel::<NodeCommand>();

    tokio::spawn(async move {
        let node_dir = input_dir.join(format!("node_{node_id}"));
        let mut presig_pool: Option<FifoQueue<Presignature<Secp256k1>>> = None;

        while let Some(cmd) = rx.recv().await {
            match cmd {
                NodeCommand::Init { reply } => {
                    let result = (|| -> NodeResult<usize> {
                        if !node_dir.exists() {
                            return Err(format!(
                                "node directory not found: {}",
                                node_dir.display()
                            ));
                        }

                        let pool = load_presig_pool(&node_dir)?;
                        let size = pool.len();
                        presig_pool = Some(pool);
                        Ok(size)
                    })();

                    let _ = reply.send(result);
                }
                NodeCommand::Sign { payload, reply } => {
                    let result = (|| -> NodeResult<PartialSignature<Secp256k1>> {
                        let pool = presig_pool
                            .as_mut()
                            .ok_or_else(|| "node is not initialized".to_string())?;

                        let presig = pool
                            .pop_next()
                            .ok_or_else(|| "presig pool exhausted".to_string())?;

                        let msg = if prehashed {
                            let scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(&payload);
                            PrehashedDataToSign::from_scalar(scalar)
                                .insecure_assume_preimage_known()
                        } else {
                            DataToSign::digest::<sha2::Sha256>(&payload)
                        };
                        Ok(presig.issue_partial_signature(msg))
                    })();

                    let _ = reply.send(result);
                }
            }
        }
    });

    NodeHandle { tx, node_id }
}

/// Sends `Init` to one node and awaits pool-size response.
async fn send_init(handle: &NodeHandle) -> NodeResult<usize> {
    let (reply_tx, reply_rx) = oneshot::channel();
    handle
        .tx
        .send(NodeCommand::Init { reply: reply_tx })
        .map_err(|e| format!("send init to node {} failed: {e}", handle.node_id))?;

    reply_rx
        .await
        .map_err(|e| format!("init response from node {} failed: {e}", handle.node_id))?
}

/// Sends `Sign` command with payload bytes to one node and awaits partial signature.
async fn send_sign(
    handle: &NodeHandle,
    payload: Vec<u8>,
) -> NodeResult<PartialSignature<Secp256k1>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    handle
        .tx
        .send(NodeCommand::Sign {
            payload,
            reply: reply_tx,
        })
        .map_err(|e| format!("send sign to node {} failed: {e}", handle.node_id))?;

    reply_rx
        .await
        .map_err(|e| format!("sign response from node {} failed: {e}", handle.node_id))?
}

/// Reads one trimmed line from stdin after printing prompt.
fn read_line(prompt: &str) -> String {
    println!("{prompt}");
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("read line from stdin");
    input.trim().to_string()
}

/// Initializes all online nodes, retrying every 10 seconds until:
/// 1) every node initializes successfully, and
/// 2) all reported pool sizes are equal.
///
/// Returns the shared presignature pool size.
async fn init_all_nodes_with_retry(handles: &[NodeHandle]) -> usize {
    loop {
        let mut nodes_pool_sizes: Vec<usize> = Vec::with_capacity(handles.len());
        let mut failed_nodes: Vec<(u16, String)> = Vec::new();

        for handle in handles {
            match send_init(handle).await {
                Ok(size) => {
                    println!(
                        "[coord] Node {} initialized with presig pool size {}.",
                        handle.node_id, size
                    );
                    nodes_pool_sizes.push(size);
                }
                Err(err) => failed_nodes.push((handle.node_id, err)),
            }
        }

        if !failed_nodes.is_empty() {
            // TODO: ak failne jeden, tak sa loopuje odznova cez vsetky - zhodnotit ci to tak ma byt, alebo to dame ze sa bude retryovat len ten failnuty.
            for (node_id, err) in &failed_nodes {
                eprintln!("[coord] Init failed for node {node_id}: {err}");
            }
            println!("[coord] Retrying failed initialization in 10 seconds...");
            sleep(Duration::from_secs(10)).await;
            continue;
        }

        let first = nodes_pool_sizes[0];
        if nodes_pool_sizes.iter().any(|&size| size != first) {
            eprintln!(
                "[coord] Init mismatch: online nodes returned different pool sizes: {:?}",
                nodes_pool_sizes
            );
            println!("[coord] Retrying initialization in 10 seconds...");
            sleep(Duration::from_secs(10)).await;
            continue;
        }

        assert!(
            nodes_pool_sizes.iter().all(|&size| size == first),
            "all initialized node pool sizes must match"
        );

        return first;
    }
}

/// Loads offline node outputs for one round from `input_dir/node_0`:
/// - `offline_partial_sig_<round>.msgpack`
/// - `ppd_<round>.msgpack`
///
/// After loading, it removes both files and the `node_0` directory.
fn load_offline_partial_and_ppd(
    input_dir: &Path,
    round: u64,
) -> NodeResult<(
    PartialSignature<Secp256k1>,
    StoredPresignaturePublicData<Secp256k1>,
)> {
    let node0_dir = input_dir.join("node_0");
    let partial_path = node0_dir.join(format!("offline_partial_sig_{round}.msgpack"));
    let ppd_path = node0_dir.join(format!("ppd_{round}.msgpack"));

    let partial_bytes = fs::read(&partial_path)
        .map_err(|e| format!("read {} failed: {e}", partial_path.display()))?;
    let partial_sig: PartialSignature<Secp256k1> = rmp_serde::from_slice(&partial_bytes)
        .map_err(|e| format!("deserialize {} failed: {e}", partial_path.display()))?;

    let ppd_bytes =
        fs::read(&ppd_path).map_err(|e| format!("read {} failed: {e}", ppd_path.display()))?;
    let stored_ppd: StoredPresignaturePublicData<Secp256k1> = rmp_serde::from_slice(&ppd_bytes)
        .map_err(|e| format!("deserialize {} failed: {e}", ppd_path.display()))?;

    fs::remove_file(&partial_path)
        .map_err(|e| format!("delete {} failed: {e}", partial_path.display()))?;
    fs::remove_file(&ppd_path).map_err(|e| format!("delete {} failed: {e}", ppd_path.display()))?;
    fs::remove_dir(&node0_dir)
        .map_err(|e| format!("delete {} failed: {e}", node0_dir.display()))?;

    Ok((partial_sig, stored_ppd))
}

/// Serializes and writes final combined signature to
/// `output_dir/signatures/signature_<round>.msgpack`.
fn export_signature(
    output_dir: &Path,
    round: u64,
    signature: &Signature<Secp256k1>,
) -> NodeResult<PathBuf> {
    let sig_dir = output_dir.join("signatures");
    fs::create_dir_all(&sig_dir)
        .map_err(|e| format!("create {} failed: {e}", sig_dir.display()))?;

    let sig_path = sig_dir.join(format!("signature_{round}.msgpack"));
    let bytes = rmp_serde::to_vec_named(signature) // TODO: zistit ci treba "named", ci nestaci pure
        .map_err(|e| format!("serialize signature failed: {e}"))?;
    fs::write(&sig_path, bytes).map_err(|e| format!("write {} failed: {e}", sig_path.display()))?;
    Ok(sig_path)
}

#[tokio::main]
async fn main() {
    let prehashed = std::env::args().any(|a| a == "--prehashed");

    let n: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let input_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "./output".to_string()); // TODO: to input
    let output_dir = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "./output".to_string());

    let input_dir = PathBuf::from(input_dir);
    let output_dir = PathBuf::from(output_dir);

    if n < 2 {
        eprintln!("[coord] n must be >= 2 (node_0 offline + at least one online node)");
        return;
    }

    let handles: Vec<NodeHandle> = (1..n)
        .map(|node_id| spawn_online_node(node_id, input_dir.clone(), prehashed))
        .collect();

    println!(
        "[coord] Spawned {} online nodes (input: {}, output: {}).",
        handles.len(),
        input_dir.display(),
        output_dir.display()
    );

    let mut remaining_presigs = init_all_nodes_with_retry(&handles).await;
    println!(
        "[coord] All online nodes initialized. Shared pool size = {}.",
        remaining_presigs
    );

    let mut round: u64 = 0;

    loop {
        if remaining_presigs == 0 {
            println!(
                "[coord] Presig pools exhausted. Provide fresh pools and press ENTER to reinitialize online nodes..."
            );
            let _ = read_line("");
            remaining_presigs = init_all_nodes_with_retry(&handles).await;
            println!(
                "[coord] Online nodes reinitialized. Shared pool size = {}.",
                remaining_presigs
            );
        }

        let payload_name = read_line("[coord] Enter payload file name from input directory:");
        if payload_name.is_empty() {
            eprintln!("[coord] Empty payload file name. Try again.");
            continue;
        }

        let payload_path = input_dir.join(&payload_name);
        let payload = match fs::read(&payload_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("[coord] Failed to read {}: {e}", payload_path.display());
                continue;
            }
        };

        println!(
            "[coord] Dispatching payload ({} bytes) to {} online nodes...",
            payload.len(),
            handles.len()
        );

        let mut online_partials: Vec<PartialSignature<Secp256k1>> =
            Vec::with_capacity(handles.len());
        let mut online_errors: Vec<(u16, String)> = Vec::new();

        for handle in &handles {
            match send_sign(handle, payload.clone()).await {
                Ok(partial) => online_partials.push(partial),
                Err(err) => online_errors.push((handle.node_id, err)),
            }
        }

        if !online_errors.is_empty() {
            for (node_id, err) in &online_errors {
                eprintln!("[coord] Sign failed on node {node_id}: {err}");
            }
            println!(
                "[coord] Online signing encountered errors; forcing pool reload before next payload."
            );
            remaining_presigs = 0;
            continue;
        }

        println!(
            "[coord] Received all {} online partial signatures.",
            online_partials.len()
        );

        println!(
            "[coord] Waiting for offline node output for round {round}. After offline signing is done, press ENTER to continue..."
        );

        let (offline_partial, ppd) = loop {
            let _ = read_line("");
            match load_offline_partial_and_ppd(&input_dir, round) {
                Ok(values) => break values,
                Err(err) => {
                    eprintln!(
                        "[coord] Offline output not ready or invalid for round {round}: {err}"
                    );
                    println!(
                        "[coord] Fix files and press ENTER to retry loading offline output..."
                    );
                }
            }
        };

        let msg = if prehashed {
            let scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(&payload);
            PrehashedDataToSign::from_scalar(scalar).insecure_assume_preimage_known()
        } else {
            DataToSign::digest::<sha2::Sha256>(&payload)
        };
        let mut all_partials = Vec::with_capacity(n as usize);
        all_partials.push(offline_partial);
        all_partials.extend(online_partials);

        let signature = match PartialSignature::combine(&all_partials, &ppd.public, msg) {
            Some(sig) => sig,
            None => {
                eprintln!(
                    "[coord] Failed to combine partial signatures for round {round}. Discarding this round and reloading pools."
                );
                remaining_presigs = 0;
                round += 1;
                continue;
            }
        };

        match export_signature(&output_dir, round, &signature) {
            Ok(path) => {
                println!(
                    "[coord] Round {round} complete. Final signature exported to {}",
                    path.display()
                );
            }
            Err(err) => {
                eprintln!("[coord] Failed to export signature for round {round}: {err}");
            }
        }

        remaining_presigs -= 1;
        round += 1;
    }
}
