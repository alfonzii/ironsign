use anyhow::Result;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{self, DataToSign, ExecutionId, PregeneratedPrimes, Signature};
use futures::future::try_join_all;
use futures::{Sink, Stream};
use rand::rngs::OsRng;
use round_based::{
    Incoming, MessageDestination, MessageType, MpcParty, MsgId, Outgoing, PartyIndex,
};
use sha2::Sha256;
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::sync::mpsc;

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

#[tokio::main]
async fn main() -> Result<()> {
    let n: u16 = 3;
    let aux_infos = run_aux_info_once(n).await?;
    let key_shares = run_keygen_once_n_of_n(n, aux_infos).await?;

    let sig = run_sign_once_n_of_n(n, key_shares).await?;
    let r_bytes = sig.r.to_be_bytes();
    let s_bytes = sig.normalize_s().s.to_be_bytes(); // low-s
    println!("  r (32B, BE): {}", hex::encode(r_bytes));
    println!("  s (32B, BE, low-s): {}", hex::encode(s_bytes));
    Ok(())
}
