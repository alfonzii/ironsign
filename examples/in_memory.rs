use anyhow::{Result, anyhow};
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{self, DataToSign, ExecutionId, PregeneratedPrimes, Signature};
use futures::future::try_join_all;
use futures::{Sink, Stream};
use rand::rngs::OsRng;
use round_based::{
    Incoming, MessageDestination, MessageType, MpcParty, MsgId, Outgoing, PartyIndex,
};
use sha2::Sha256;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::sync::mpsc;

type PresigTuple = (
    cggmp24::Presignature<Secp256k1>,
    cggmp24::signing::PresignaturePublicData<Secp256k1>,
);

struct PresignatureSet {
    presigs: Vec<cggmp24::Presignature<Secp256k1>>, // one per party, in party-id order
    commitments: cggmp24::signing::PresignaturePublicData<Secp256k1>,
}

impl PresignatureSet {
    fn from_raw(n: u16, raw: Vec<PresigTuple>) -> Result<Self> {
        if raw.len() != n as usize {
            return Err(anyhow!("expected {n} presigs, got {}", raw.len()));
        }

        // All parties should return the same PresignaturePublicData; use party 0's copy.
        let commitments = raw[0].1.clone();
        if commitments.commitments.len() != n as usize {
            return Err(anyhow!(
                "commitments length mismatch: expected {n}, got {}",
                commitments.commitments.len()
            ));
        }

        // Check that all parties have identical commitments
        for (i, (_, pub_data)) in raw.iter().enumerate().skip(1) {
            if pub_data != &commitments {
                return Err(anyhow!(
                    "commitments mismatch at party {i}: expected equal commitments from all parties"
                ));
            }
        }

        let presigs = raw.into_iter().map(|(p, _pub)| p).collect();
        Ok(Self {
            presigs,
            commitments,
        })
    }
}

type PresignaturePool = VecDeque<PresignatureSet>;

// Return the list of recipient party indices based on the destination type
fn resolve_recipients(me: PartyIndex, n: u16, dest: MessageDestination) -> Vec<PartyIndex> {
    match dest {
        MessageDestination::OneParty(party_id) => vec![party_id],
        MessageDestination::AllParties => (0..n).filter(|&party_id| party_id != me).collect(),
    }
}

// --------------------
// Router (shared core)
// --------------------
struct Router<M> {
    n: u16,
    next_id_by_sender: Mutex<Vec<MsgId>>,
    inboxes: Vec<mpsc::UnboundedSender<Incoming<M>>>,
}

impl<M> Router<M> {
    fn new(n: u16) -> (Arc<Self>, Vec<mpsc::UnboundedReceiver<Incoming<M>>>) {
        let mut inbox_senders = Vec::with_capacity(n as usize);
        let mut inbox_receivers = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (tx, rx) = mpsc::unbounded_channel();
            inbox_senders.push(tx);
            inbox_receivers.push(rx);
        }
        let router = Arc::new(Self {
            n,
            next_id_by_sender: Mutex::new(vec![0; n as usize]),
            inboxes: inbox_senders,
        });
        (router, inbox_receivers)
    }

    fn next_msg_id(&self, sender: PartyIndex) -> MsgId {
        let mut table = self.next_id_by_sender.lock().unwrap();
        let id = table[sender as usize];
        table[sender as usize] += 1;
        id
    }

    fn deliver(&self, to: PartyIndex, incoming: Incoming<M>) {
        // Best-effort deliver; in production, handle errors/backpressure.
        let _ = self.inboxes[to as usize].send(incoming);
    }
}

// --------------------
// Sink side (per party)
// --------------------
#[derive(Clone)]
struct OutSink<M> {
    me: PartyIndex,
    router: Arc<Router<M>>,
}

impl<M> OutSink<M> {
    fn new(me: PartyIndex, router: Arc<Router<M>>) -> Self {
        Self { me, router }
    }
}

impl<M: Clone + Send + 'static> Sink<Outgoing<M>> for OutSink<M> {
    type Error = Infallible;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Outgoing<M>) -> Result<(), Self::Error> {
        let me = self.me;
        let id = self.router.next_msg_id(me);
        let msg_type = match item.recipient {
            MessageDestination::AllParties => MessageType::Broadcast,
            MessageDestination::OneParty(_) => MessageType::P2P,
        };
        let recipients = resolve_recipients(me, self.router.n, item.recipient);
        for to in recipients {
            let incoming = Incoming {
                id,
                sender: me,
                msg_type,
                msg: item.msg.clone(), // clone per recipient (OK for small demo)
            };
            self.router.deliver(to, incoming);
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

// ----------------------
// Stream side (per party)
// ----------------------
struct Inbox<M> {
    rx: mpsc::UnboundedReceiver<Incoming<M>>,
}

impl<M> Inbox<M> {
    fn new(rx: mpsc::UnboundedReceiver<Incoming<M>>) -> Self {
        Self { rx }
    }
}

impl<M> Stream for Inbox<M> {
    type Item = Result<Incoming<M>, Infallible>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.rx).poll_recv(cx) {
            Poll::Ready(Some(msg)) => Poll::Ready(Some(Ok(msg))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ------------------------------
// Factory: build N party pairs
// ------------------------------
fn make_memory_deliveries<M: Clone + Send + 'static>(n: u16) -> Vec<(Inbox<M>, OutSink<M>)> {
    let (router, rxs) = Router::<M>::new(n);
    (0..n)
        .zip(rxs.into_iter())
        .map(|(party_id, rx)| {
            let inbox = Inbox::new(rx);
            let sink = OutSink::new(party_id, router.clone());
            (inbox, sink)
        })
        .collect()
}

// ------------------------------------------- CGGMP --------------------------------------------------------------------

async fn run_aux_info_once(n: u16) -> anyhow::Result<Vec<cggmp24::key_share::AuxInfo>> {
    // Build deliveries using the protocol's message type:
    // We infer the msg type from the AuxInfo protocol.
    let parties = make_memory_deliveries(n);
    let eid = ExecutionId::new(b"aux-info-demo");

    // Spawn one task per party
    let handles = (0..n).zip(parties.into_iter()).map(|(party_id, delivery)| {
        let party = MpcParty::connected(delivery);

        tokio::spawn(async move {
            println!("party {party_id}: generating primes");
            let primes = PregeneratedPrimes::generate(&mut OsRng);
            println!("party {party_id}: aux-info start");
            cggmp24::aux_info_gen(eid, party_id, n, primes)
                .start(&mut OsRng, party)
                .await
                .unwrap() // fine for demo
        })
    });

    // Await results
    let aux_infos: Vec<_> = try_join_all(handles).await?;

    Ok(aux_infos)
}

async fn run_keygen_once_n_of_n(
    n: u16,
    aux_infos: Vec<cggmp24::key_share::AuxInfo>,
) -> Result<Vec<cggmp24::KeyShare<Secp256k1>>> {
    // Fresh deliveries for keygen (message type differs from Aux-Info)
    let parties = make_memory_deliveries(n);
    let eid = ExecutionId::new(b"dkg-n-of-n");

    // Spawn DKG for each party; unwrap inside the task (demo simplicity)
    let handles = (0..n).zip(parties.into_iter()).map(|(party_id, delivery)| {
        tokio::spawn(async move {
            cggmp24::keygen::<Secp256k1>(eid, party_id, n)
                .start(&mut OsRng, MpcParty::connected(delivery))
                .await
                .unwrap()
        })
    });

    // Gather incomplete shares
    let incomplete = try_join_all(handles).await?; // Vec<IncompleteKeyPart>

    // Pair each incomplete part with its AuxInfo → final KeyShare
    let key_shares: Vec<_> = incomplete
        .into_iter()
        .zip(aux_infos)
        .map(|(k, a)| cggmp24::KeyShare::from_parts((k, a)).unwrap())
        .collect();

    Ok(key_shares)
}

async fn run_sign_once_n_of_n(
    n: PartyIndex,
    key_shares: Vec<cggmp24::KeyShare<Secp256k1>>,
) -> Result<Signature<Secp256k1>> {
    // Active set: everyone, in keygen order 0..n-1
    let keygen_indexes: Vec<PartyIndex> = (0..n).collect();

    // Build deliveries for the signing phase
    let parties = make_memory_deliveries(n);

    // Prepare the message (as a digest)
    let msg = DataToSign::digest::<Sha256>(b"hello from signing demo");

    // Keep public key before we move key_shares into the iterator
    let public_key = key_shares[0].shared_public_key.clone();

    let handles = (0..n)
        .zip(parties.into_iter())
        .zip(key_shares.into_iter())
        .map(|((party_id, delivery), key_share)| {
            let party = MpcParty::connected(delivery);
            let eid = ExecutionId::new(b"signing-n-of-n");
            let keygen_indexes = keygen_indexes.clone();

            tokio::spawn(async move {
                cggmp24::signing(eid, party_id, &keygen_indexes, &key_share)
                    .sign(&mut OsRng, party, &msg)
                    .await
                    .unwrap() // demo simplicity
            })
        });

    let sigs = try_join_all(handles).await?;

    let sig0 = sigs[0].clone();
    assert!(
        sigs.iter().all(|s| s == &sig0),
        "signatures must match across parties"
    );

    let verified = sig0.verify(public_key.as_ref(), &msg).is_ok();

    println!("Signing finished (n-of-n).");
    println!("  verified: {}", if verified { "OK" } else { "FAILED" });

    Ok(sig0)
}

async fn run_presignatures_once_n_of_n(
    n: u16,
    key_shares: Vec<cggmp24::KeyShare<Secp256k1>>,
) -> Result<
    Vec<(
        cggmp24::Presignature<Secp256k1>,
        cggmp24::signing::PresignaturePublicData<Secp256k1>,
    )>,
> {
    // Fresh deliveries for presignature generation (same message family as signing)
    let parties = make_memory_deliveries(n);

    // Active set: everyone, in keygen order 0..n-1
    let parties_indexes_at_keygen: Vec<PartyIndex> = (0..n).collect();

    // One timestamp per function call => unique eid across calls, same eid across parties in this call
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();

    let handles = (0..n)
        .zip(parties.into_iter())
        .zip(key_shares.into_iter())
        .map(|((party_id, delivery), key_share)| {
            let keygen_indexes = parties_indexes_at_keygen.clone();

            tokio::spawn(async move {
                // Important: all parties must use the SAME eid for this execution
                let eid_str = format!("presig-n-of-n-{ts}");
                let eid = ExecutionId::new(eid_str.as_bytes());

                cggmp24::signing(eid, party_id, &keygen_indexes, &key_share)
                    .generate_presignature(&mut OsRng, MpcParty::connected(delivery))
                    .await
                    .unwrap() // fine for demo
            })
        });

    let presigs = try_join_all(handles).await?;
    println!("Presignatures finished.");

    Ok(presigs)
}

async fn build_presignature_pool_n_of_n(
    n: u16,
    key_shares: &[cggmp24::KeyShare<Secp256k1>],
    k: usize,
) -> Result<PresignaturePool> {
    let mut pool = VecDeque::with_capacity(k);

    for i in 0..k {
        println!("Presignature set {}/{}:", i + 1, k);

        let raw = run_presignatures_once_n_of_n(n, key_shares.to_vec()).await?;
        pool.push_back(PresignatureSet::from_raw(n, raw)?);
    }

    Ok(pool)
}

fn sign_with_presig_set_n_of_n(
    key_shares: &[cggmp24::KeyShare<Secp256k1>],
    presig_set: PresignatureSet, // taken by value => consumed
    msg_bytes: &[u8],
) -> Result<Signature<Secp256k1>> {
    // Precompute the digest once.
    let msg_digest = DataToSign::digest::<Sha256>(msg_bytes);

    // Each presignature is consumed here (one-time use).
    let partial_sigs: Vec<_> = presig_set
        .presigs
        .into_iter()
        .map(|p| p.issue_partial_signature(msg_digest))
        .collect();

    let sig = cggmp24::PartialSignature::combine(
        &partial_sigs,
        &presig_set.commitments,
        DataToSign::digest::<Sha256>(msg_bytes),
    )
    .ok_or_else(|| anyhow!("combine returned None (malformed input or cheating detected)"))?;

    // Verify (must do this!)
    let pk = key_shares[0].shared_public_key;
    let verified = sig
        .verify(pk.as_ref(), &DataToSign::digest::<Sha256>(msg_bytes))
        .is_ok();

    println!("Signing finished (presignatures).");
    println!("  verified: {}", if verified { "OK" } else { "FAILED" });

    Ok(sig)
}

#[tokio::main]
async fn main() -> Result<()> {
    let n = 3;
    let aux_infos = run_aux_info_once(n).await?;
    let key_shares = run_keygen_once_n_of_n(n, aux_infos).await?;

    let mut pool = build_presignature_pool_n_of_n(n, &key_shares, 5).await?; // 5 messages max

    for msg in [b"m1", b"m2", b"m3", b"m4", b"m5"] {
        let set = pool.pop_front().expect("presignature pool empty");
        let sig = sign_with_presig_set_n_of_n(&key_shares, set, msg)?;
        println!("  r: {}", hex::encode(sig.r.to_be_bytes()));
        println!("  s: {}", hex::encode(sig.normalize_s().s.to_be_bytes()));
    }
    Ok(())
}
