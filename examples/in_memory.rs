use anyhow::Result;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{self, ExecutionId, PregeneratedPrimes};
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand::rngs::OsRng;
use round_based::{
    Incoming, MessageDestination, MessageType, MpcParty, MsgId, Outgoing, PartyIndex,
};
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
fn make_memory_deliveries<M: Clone + Send + 'static>(n: u16) -> Vec<(OutSink<M>, Inbox<M>)> {
    let (router, mut rxs) = Router::<M>::new(n);
    (0..n)
        .map(|party_id| {
            let sink = OutSink::new(party_id, router.clone());
            let inbox = Inbox::new(rxs.remove(0));
            (sink, inbox)
        })
        .collect()
}

// ------------------------------
// Example: run Aux-Info once
// ------------------------------
async fn run_aux_info_once(n: u16) -> anyhow::Result<Vec<cggmp24::key_share::AuxInfo>> {
    // Build deliveries using the protocol's message type:
    // We infer the msg type from the AuxInfo protocol.
    let mut parties = make_memory_deliveries(n);

    // Spawn one task per party
    let mut handles = Vec::with_capacity(n as usize);
    for party_id in 0..n {
        let (out_sink, inbox) = parties.remove(0);

        // CGGMP expects (incoming, outgoing)
        let delivery = (inbox, out_sink);
        let party = MpcParty::connected(delivery);
        let eid = ExecutionId::new(b"aux-info-demo");

        handles.push(tokio::spawn(async move {
            println!("Starting generating primes for party {}", party_id);
            let primes = PregeneratedPrimes::generate(&mut OsRng);
            println!("Starting aux-info-gen for party {}", party_id);
            cggmp24::aux_info_gen(eid, party_id, n, primes)
                .start(&mut OsRng, party)
                .await
        }));
    }

    // Collect results
    let mut out = Vec::with_capacity(n as usize);
    for h in handles {
        out.push(h.await??);
    }
    Ok(out)
}

async fn run_keygen_once_n_of_n(
    n: u16,
    aux_infos: Vec<cggmp24::key_share::AuxInfo>,
) -> Result<Vec<cggmp24::KeyShare<Secp256k1>>> {
    // New deliveries for this phase (different Msg type than Aux-Info)
    let mut parties = make_memory_deliveries(n);

    // Spawn DKG for each party
    let mut handles = Vec::with_capacity(n as usize);
    for party_id in 0..n {
        let (out_sink, inbox) = parties.remove(0);
        let delivery = (inbox, out_sink); // (incoming, outgoing)
        let party = MpcParty::connected(delivery);

        let eid = ExecutionId::new(b"dkg-n-of-n");
        handles.push(tokio::spawn(async move {
            cggmp24::keygen::<Secp256k1>(eid, party_id, n)
                .start(&mut OsRng, party)
                .await
        }));
    }

    // Collect incomplete shares
    let mut incomplete = Vec::with_capacity(n as usize);
    for h in handles {
        incomplete.push(h.await??);
    }

    // Pair each incomplete part with its AuxInfo → final KeyShare
    let mut key_shares = Vec::with_capacity(n as usize);
    for (ik, aux) in incomplete.into_iter().zip(aux_infos.into_iter()) {
        key_shares.push(cggmp24::KeyShare::from_parts((ik, aux))?);
    }
    Ok(key_shares)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Build 3 parties wired through the in-memory router
    let n: u16 = 3;
    let mut parties = make_memory_deliveries::<String>(n);

    // Unpack party pairs (sink, inbox)
    let (_sink0, mut inbox0) = parties.remove(0);
    let (mut sink1, _inbox1) = parties.remove(0);
    let (mut sink2, mut inbox2) = parties.remove(0);

    // SPAWN RECEIVERS:
    // party0 expects TWO messages (broadcast from 1, p2p from 2)
    let r0 = tokio::spawn(async move {
        for i in 0..2 {
            if let Some(Ok(incoming)) = inbox0.next().await {
                println!(
                    "party0 recv {}: id={}, from={}, type={:?}, msg={:?}",
                    i, incoming.id, incoming.sender, incoming.msg_type, incoming.msg
                );
            }
        }
    });
    // party2 expects ONE message (broadcast from 1). Party1 receives nothing
    let r2 = tokio::spawn(async move {
        if let Some(Ok(incoming)) = inbox2.next().await {
            println!(
                "party2 recv: id={}, from={}, type={:?}, msg={:?}",
                incoming.id, incoming.sender, incoming.msg_type, incoming.msg
            );
        }
    });

    // SENDER ACTIONS:
    // 1) party1 broadcasts (goes to 0 and 2; same MsgId on both)
    sink1
        .send(Outgoing {
            recipient: MessageDestination::AllParties,
            msg: "hello all".to_string(),
        })
        .await?;

    // 2) party2 sends P2P to party0 (only 0 receives)
    sink2
        .send(Outgoing {
            recipient: MessageDestination::OneParty(0),
            msg: "hi 0".to_string(),
        })
        .await?;

    // Wait for receivers to print what they got
    r0.await?;
    r2.await?;

    // ----------------------------------
    println!("\n--- Aux-Info example ---");

    // CGGMP example
    let n: u16 = 3;
    let aux_infos = run_aux_info_once(n).await?;
    let key_shares = run_keygen_once_n_of_n(n, aux_infos).await?;
    println!("DKG n-of-n OK, produced {} KeyShares", key_shares.len());
    Ok(())
}
