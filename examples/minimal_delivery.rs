//! Minimal end-to-end CGGMP21 demo using a hand-written Delivery implementation.
//!
//! The example spins up three parties, wires them through an in-process router that
//! satisfies [`round_based::Delivery`], and runs:
//! 1. Threshold key generation
//! 2. Auxiliary info generation
//! 3. Threshold signing of a single message
//!
//! Each step prints progress so you can follow the data flow.

use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use futures::{
    Sink, Stream,
    channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded},
};
use rand::rngs::OsRng;
use round_based::{
    Delivery, Incoming, MessageDestination, MessageType, MpcParty, Outgoing, PartyIndex,
};
use sha2::Sha256;
use tokio::task::JoinHandle;

use cggmp21::{
    ExecutionId, PregeneratedPrimes, Signature,
    key_refresh::AuxOnlyMsg,
    key_share::KeyShare,
    keygen::ThresholdMsg,
    security_level::SecurityLevel128,
    signing::{DataToSign, msg::Msg as SigningMsg},
    supported_curves::Secp256k1,
};

// -------------------------------------------------------------------------------------------------
// Transport layer
// -------------------------------------------------------------------------------------------------

/// In-memory router that fans messages out to the registered parties.
///
/// Responsibilities:
/// - Maintains one inbox (UnboundedSender) per party
/// - Assigns monotonically increasing message IDs
/// - Routes:
///   * P2P via MessageDestination::OneParty
///   * Broadcast via MessageDestination::AllParties
///
/// Notes:
/// - No authentication, ordering guarantees, or backpressure
/// - Suitable for demos/tests only
struct Router<M> {
    inboxes: Vec<UnboundedSender<Result<Incoming<M>, Infallible>>>,
    next_id: AtomicU64,
    parties: u16,
}

impl<M: Clone + Send + 'static> Router<M> {
    /// Routes an Outgoing<M> from `from` to either one party or all parties.
    /// Converts it into an Incoming<M> with msg_type set appropriately.
    fn route(&self, from: PartyIndex, outgoing: Outgoing<M>) {
        match outgoing.recipient {
            MessageDestination::OneParty(target) => {
                let incoming = Incoming {
                    id: self.next_id.fetch_add(1, Ordering::Relaxed),
                    sender: from,
                    msg_type: MessageType::P2P,
                    msg: outgoing.msg,
                };
                self.inboxes[usize::from(target)]
                    .unbounded_send(Ok(incoming))
                    .expect("p2p delivery");
            }
            MessageDestination::AllParties => {
                for (party_idx, inbox) in self.inboxes.iter().enumerate() {
                    let incoming = Incoming {
                        id: self.next_id.fetch_add(1, Ordering::Relaxed),
                        sender: from,
                        msg_type: MessageType::Broadcast,
                        msg: outgoing.msg.clone(),
                    };
                    inbox
                        .unbounded_send(Ok(incoming))
                        .expect("broadcast delivery");
                }
            }

            other => panic!("unsupported destination: {other:?}"),
        }
    }
}

/// Stream wrapper for incoming protocol messages.
///
/// This is the `Receive` half of `Delivery<M>`.
/// It simply forwards items from the party's inbox.
struct PartyStream<M> {
    inner: UnboundedReceiver<Result<Incoming<M>, Infallible>>,
}

impl<M> Stream for PartyStream<M> {
    type Item = Result<Incoming<M>, Infallible>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

/// Sink wrapper for outgoing protocol messages.
///
/// This is the `Send` half of `Delivery<M>`.
/// It forwards `Outgoing<M>` into the shared Router.
struct PartySink<M> {
    party_id: PartyIndex,
    router: Arc<Router<M>>,
}

impl<M: Clone + Send + 'static> Sink<Outgoing<M>> for PartySink<M> {
    type Error = Infallible;

    fn poll_ready(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Outgoing<M>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.router.route(this.party_id, item);
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Delivery implementation returned to each party.
struct LocalDelivery<M> {
    router: Arc<Router<M>>,
    receiver: PartyStream<M>,
    party_id: PartyIndex,
}

impl<M: Clone + Send + 'static> Delivery<M> for LocalDelivery<M> {
    type Send = PartySink<M>;
    type Receive = PartyStream<M>;
    type SendError = Infallible;
    type ReceiveError = Infallible;

    fn split(self) -> (Self::Receive, Self::Send) {
        let LocalDelivery {
            router,
            receiver,
            party_id,
        } = self;
        let sink = PartySink { router, party_id };
        (receiver, sink)
    }
}

/// LocalNetwork hands out one LocalDelivery per party.
///
/// Internals:
/// - Creates N independent inboxes
/// - Connects a party by returning its `(receiver, sink)`
/// - All parties share a single Router reference
struct LocalNetwork<M> {
    router: Arc<Router<M>>,
    receivers: Vec<Mutex<Option<UnboundedReceiver<Result<Incoming<M>, Infallible>>>>>,
}

impl<M: Clone + Send + 'static> LocalNetwork<M> {
    /// Creates an in-process network for `n` parties.
    fn new(n: u16) -> Self {
        let mut inboxes = Vec::with_capacity(n as usize);
        let mut receivers = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (tx, rx) = unbounded();
            inboxes.push(tx);
            receivers.push(Mutex::new(Some(rx)));
        }
        let router = Arc::new(Router {
            inboxes,
            next_id: AtomicU64::new(0),
            parties: n,
        });
        Self { router, receivers }
    }

    /// Returns a Delivery for party `party_id`.
    /// Panics if the party connects twice.
    fn connect(&self, party_id: PartyIndex) -> LocalDelivery<M> {
        let receiver = self.receivers[usize::from(party_id)]
            .lock()
            .expect("lock poisoned")
            .take()
            .expect("party already connected");
        LocalDelivery {
            router: Arc::clone(&self.router),
            receiver: PartyStream { inner: receiver },
            party_id,
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Protocol helpers
// -------------------------------------------------------------------------------------------------

/// Runs threshold key generation for all parties over LocalNetwork.
///
/// - Spawns N async tasks, each with its own Delivery
/// - Executes `cggmp21::keygen::<Secp256k1>`
/// - Returns `Vec<IncompleteKeyShare>`
async fn run_keygen(parties: u16, threshold: u16) -> Vec<cggmp21::IncompleteKeyShare<Secp256k1>> {
    let network: Arc<LocalNetwork<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>> =
        Arc::new(LocalNetwork::new(parties));

    let mut handles: Vec<JoinHandle<(PartyIndex, cggmp21::IncompleteKeyShare<Secp256k1>)>> =
        Vec::with_capacity(parties as usize);

    let eid = ExecutionId::new(b"in-memory-keygen");

    for i in 0..parties {
        let delivery = network.connect(i);
        handles.push(tokio::spawn(async move {
            let mut rng = OsRng;
            let party = MpcParty::connected(delivery);
            let share = cggmp21::keygen::<Secp256k1>(eid, i, parties)
                .set_threshold(threshold)
                .start(&mut rng, party)
                .await
                .expect("keygen transport");
            (i, share)
        }));
    }

    collect_ordered(handles, parties)
        .await
        .into_iter()
        .collect()
}

/// Runs auxiliary info generation for all parties over LocalNetwork.
///
/// - Spawns N tasks with their Delivery
/// - Generates primes with `PregeneratedPrimes`
/// - Executes `cggmp21::aux_info_gen`
/// - Returns `Vec<AuxInfo>`
async fn run_aux_generation(parties: u16) -> Vec<cggmp21::key_share::AuxInfo> {
    let network: Arc<LocalNetwork<AuxOnlyMsg<Sha256, SecurityLevel128>>> =
        Arc::new(LocalNetwork::new(parties));

    let mut handles: Vec<JoinHandle<(PartyIndex, cggmp21::key_share::AuxInfo)>> =
        Vec::with_capacity(parties as usize);

    let eid = ExecutionId::new(b"in-memory-aux");

    for i in 0..parties {
        let delivery = network.connect(i);
        handles.push(tokio::spawn(async move {
            let mut rng = OsRng;
            let primes = PregeneratedPrimes::<SecurityLevel128>::generate(&mut rng);
            let party = MpcParty::connected(delivery);
            let aux = cggmp21::aux_info_gen(eid, i, parties, primes)
                .start(&mut rng, party)
                .await
                .expect("aux transport");
            (i, aux)
        }));
    }

    collect_ordered(handles, parties)
        .await
        .into_iter()
        .collect()
}

/// Runs n-of-n signing using the previously produced key shares.
///
/// - Spawns N tasks with their Delivery
/// - Uses `cggmp21::signing(...).sign(...)`
/// - Collects identical signatures from all tasks and returns one
async fn run_signing(
    key_shares: Arc<Vec<KeyShare<Secp256k1>>>,
    message: DataToSign<Secp256k1>,
) -> Signature<Secp256k1> {
    let parties = key_shares.len() as u16;
    let participants: Arc<Vec<u16>> = Arc::new((0..parties).collect());

    let network: Arc<LocalNetwork<SigningMsg<Secp256k1, Sha256>>> =
        Arc::new(LocalNetwork::new(parties));

    let mut handles: Vec<JoinHandle<(PartyIndex, Signature<Secp256k1>)>> =
        Vec::with_capacity(parties as usize);

    let eid = ExecutionId::new(b"in-memory-sign");

    for i in 0..parties {
        let delivery = network.connect(i);
        let shares = Arc::clone(&key_shares);
        let participants = Arc::clone(&participants);
        handles.push(tokio::spawn(async move {
            let mut rng = OsRng;
            let party = MpcParty::connected(delivery);
            let signature = cggmp21::signing(eid, i, &participants, &shares[usize::from(i)])
                .sign(&mut rng, party, message.clone())
                .await
                .expect("signing transport");
            // .expect_ok()
            // .expect_eq();
            (i, signature)
        }));
    }

    let signatures = collect_ordered(handles, parties).await;
    let first = signatures
        .into_iter()
        .next()
        .expect("at least one signature");
    first
}

/// Collects `(party_id, value)` join handles and returns the values ordered by `party_id`.
async fn collect_ordered<T: Send + 'static>(
    handles: Vec<JoinHandle<(PartyIndex, T)>>,
    parties: u16,
) -> Vec<T> {
    let mut slots: Vec<Option<T>> = std::iter::repeat_with(|| None)
        .take(parties as usize)
        .collect();
    for handle in handles {
        let (idx, value) = handle.await.expect("task join");
        slots[usize::from(idx)] = Some(value);
    }
    slots
        .into_iter()
        .map(|slot| slot.expect("missing task output"))
        .collect()
}

// -------------------------------------------------------------------------------------------------
// Demo entry point
// -------------------------------------------------------------------------------------------------

/// Orchestrates the full pipeline:
/// 1) Keygen -> IncompleteKeyShare
/// 2) Aux-info -> AuxInfo
/// 3) Complete shares -> KeyShare
/// 4) Sign -> Signature, then verify against shared public key
#[tokio::main]
async fn main() {
    const N: u16 = 3;
    const T: u16 = 3;

    println!("▶️  Key generation ({T}-of-{N})");
    let incomplete = run_keygen(N, T).await;

    println!("▶️  Auxiliary info generation");
    let aux = run_aux_generation(N).await;

    println!("▶️  Completing key shares");
    let key_shares: Vec<_> = incomplete
        .into_iter()
        .zip(aux)
        .map(|(share, aux)| KeyShare::from_parts((share, aux)).expect("valid key share"))
        .collect();

    println!("▶️  Signing");
    let message = DataToSign::digest::<Sha256>(b"In-memory transport example");
    let signature = run_signing(Arc::new(key_shares.clone()), message).await;

    println!(
        "✅  Signature ready: r = {:?}, s = {:?}",
        signature.r, signature.s
    );

    let public_key = key_shares[0].shared_public_key;
    signature
        .verify(&public_key, &message)
        .expect("signature verification");

    println!("🔐  Verification succeeded");
}
