# ironsign

> [!WARNING]
> This project is in early development and is not guaranteed to be secure or stable. Use at your own risk.

Prototype of an MPC/TSS-based Bitcoin signing system with:

- initialization in a controlled environment,
- simulated runtime with coordinator + online nodes,
- one offline signing node,
- Bitcoin regtest demo through an auxiliary BTC layer.

> **Status:** Work in progress.  
> This README currently focuses on how to run the demo prototype.

## Overview

**WIP**

## What this demo shows

**WIP**

<!-- This project demonstrates:

- MPC/TSS-style signing with one offline node
- initialization and export of signing state
- runtime signing with online nodes and a coordinator
- offline partial signature generation
- Bitcoin SegWit transaction flow on local regtest -->

## Repository structure

Main runnable parts:

- `initialization`  
  Generates cryptographic state for all nodes.

- `coord_runtime`  
  Represents the runtime environment with coordinator and the online nodes.

- `offline_node`  
  Offline signer running on a separate machine.

- `btc_auxiliary`  
  Builds and finalizes Bitcoin SegWit transactions and interacts with regtest.

- `docker-compose.yml`  
  Starts a local Bitcoin Core regtest node.

## Running binaries

Depending on your workflow, you can either:

- run the compiled executables directly after building the project, or
- run them through Cargo with `cargo run --release --bin <program> -- <arguments>`.

## Prerequisites

- Rust toolchain installed
- Docker + Docker Compose installed
- Two machines or two clearly separated environments:
  - **PC1** for initialization + offline node
  - **PC2** for runtime + BTC auxiliary + regtest

## CLI commands

### 1. Start regtest

```bash
docker compose up
```

To stop and remove regtest state:

```bash
docker compose down -v
```

### 2. Run initialization on PC1

```bash
./initialization -- n k dir
```

Arguments:

- `n` — total number of nodes
- `k` — size of the presignature pool
- `dir` — path to the initialization I/O dir

<!-- Behavior:
- checks whether `key_shares` already exist
- reuses existing `key_shares` if present
- otherwise generates them from scratch
- generates folders for each node with their respective `presig_pool`
- for offline node generates also public data - `ppd_pool`
- generates `pubkey`


Transfer to runtime/offline environments:

- `node_x`
- `pubkey`

Keep local:

- `key_shares` -->

### 3. Start offline node on PC1

```bash
./offline_node -- input_dir output_dir --prehashed
```

Arguments:

- `input_dir` — input folder for the offline node
- `output_dir` — output folder for the offline node
- `--prehashed` — treat incoming payload as already hashed

### 4. Start coordinator runtime on PC2

```bash
./coord_runtime -- n input_dir output_dir --prehashed
```

Arguments:

- `n` — total number of nodes
- `input_dir` — runtime input folder
- `output_dir` — runtime output folder
- `--prehashed` — treat incoming payload as already hashed

### 5. Start BTC auxiliary on PC2

```bash
./btc_auxiliary -- input_dir output_dir
```

Arguments:

- `input_dir` — input folder
- `output_dir` — output folder

### Important note to commands:

<!-- ..Because of the nature of prototype, that we are moving files here and there, it's created in a way, to be easier to orient. coord runtime and offline node both define input and output dir. Anything that the standalone programs output they put it in their defined output dir and anything they are expected to read, they try to read it from input dir.

Initialization has only one directory, with both I/O purpose, because it does not communicate with any other component. Its purpose is only for generating cryptographical content. So one folder is enough. Basically, it's just keyshares, which we try to read (as input), everything else is output. All other generated content, be it node_x folders with presig_pools, (or ppd pool for node_0), or pubkey, are moved away, as they are needed for prototype run.

Because btc auxiliary was created later, after we already had functional prototype, it is bound to coord runtime. It means, it is expected to have `input_dir` and `output_dir` set the same, as we have them for coord runtime. It's made that way, so that we don't have to move anything anywhere when we interact with coord runtime. So it is a bit counterintuitive, but from coord-runtime perspective it's great. For example, when we create payload, we save it into `input_dir` not output, because then coord_runtime when he needs payload, he will take it from input. so we dont have to copy nothing. And also, when BTC auxiliary search for signature, it will search in `output_dir`, because that dir is where coord_runtime outputs signature. So it's all from coord_runtime perspetive. -->

The prototype exchanges data through files, so each standalone component is organized around clearly defined input and output directories.

`coord_runtime` and `offline_node` both follow the same convention:

- read expected data from `input_dir`
- write produced data to `output_dir`

This makes their behavior easy to reason about when files are moved between environments.

`initialization` is different because it does not communicate with any other running component. Its only purpose is to generate cryptographic material, so it uses a single directory for both input and output.

It works as follows:

- checks whether existing `key_shares` are already present in the directory
- reuses those `key_shares` if available
- otherwise generates them from scratch
- writes newly generated node state (`node_x` folders), offline `ppd` data, and `pubkey` into the same directory

After initialization finishes, the generated outputs are moved to the locations required by the rest of the demo.

`btc_auxiliary` was added after the core runtime flow was already working, so it is intentionally aligned with `coord_runtime`.

In practice, it should use the **same `input_dir` and `output_dir`** as `coord_runtime`.

It works as follows:

- reads the **public key** from `input_dir`
- writes the **payload** into `input_dir`
- reads the **signature** from `output_dir`

This may look slightly counterintuitive at first, but it is arranged from the coordinator runtime perspective. The goal is to avoid unnecessary file copying: `btc_auxiliary` places data exactly where `coord_runtime` expects to read it from, and reads results exactly where `coord_runtime` writes them.


<!-- `btc_auxiliary` is tied to the coordinator runtime, so in practice it should use the **same input/output folders** as `coord_runtime`.

It works as follows:

- reads the **public key** from `input_dir`
- writes the **payload** into `input_dir`
- reads the **signature** from `output_dir`

This allows `btc_auxiliary` and `coord_runtime` to exchange data without manual copying. -->

## Running the full demo

Recommended flow:

### PC1
1. Run `initialization`
2. Keep `key_shares` locally
3. Transfer generated `node_x` folders and `pubkey`
4. Start `offline_node`

### PC2
1. Start Bitcoin regtest
2. Start `coord_runtime`
3. Start `btc_auxiliary`
4. Let `btc_auxiliary` generate the transaction payload
5. Let `coord_runtime` collect online partial signatures
6. Transfer offline signing request to PC1
7. Produce offline partial signature
8. Bring offline output back to PC2
9. Let `coord_runtime` combine the final signature
10. Let `btc_auxiliary` finalize and broadcast the transaction to regtest

#### Note:
While using the prototype on one device beats the whole purpose, for developer usecase we can just redirect all input and output directories into one single directory, i.e. `output`. That way, we don't have to copy and move anything, and prototype will work out. It was designed on purpose with this feature, so it can be tested easily.

## How the demo works

### Prehashed mode

`--prehashed` is required when signing Bitcoin transaction payloads.

Reason:

- `btc_auxiliary` prepares a payload that is already in hashed form
- hashing it again inside MPC runtime or offline node would produce an invalid Bitcoin signature

So for the BTC demo:

- use `--prehashed` with `coord_runtime`
- use `--prehashed` with `offline_node`

For generic random payload signing, this flag would not be needed.

## Limitations / security notes

This is a prototype / school project demo.

Current limitations include:

- manual offline transfer through files / USB
- no production-grade authentication / authorization
- no encryption of stored state
- no production-grade recovery / rollback handling
- no production-grade transport hardening

## Architecture overview

**WIP**

## Documentation

**WIP**

## License

**WIP**
