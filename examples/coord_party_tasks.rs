use anyhow::Result;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::{self, ExecutionId, PregeneratedPrimes};
use futures::future::try_join_all;
use futures::{Sink, Stream};
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
use tokio::sync::{mpsc, oneshot};

enum PartyCommand {
    RunAuxInfo {
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    Shutdown,
}

#[derive(Clone)]
struct PartyHandle {
    id: PartyIndex,
    tx: mpsc::UnboundedSender<PartyCommand>,
}

struct PartyState {
    aux_info: Option<cggmp24::key_share::AuxInfo>,
    // later:
    // key_share: Option<cggmp24::KeyShare<Secp256k1>>,
    // presig_pool: PresignaturePool,
}

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

fn spawn_party(
    party_id: PartyIndex,
    n: u16,
    delivery: (
        Inbox<cggmp24::key_refresh::msg::Msg<sha2::Sha256, SecurityLevel128>>,
        OutSink<cggmp24::key_refresh::msg::Msg<sha2::Sha256, SecurityLevel128>>,
    ),
) -> PartyHandle {
    let (tx, mut rx) = mpsc::unbounded_channel::<PartyCommand>();

    tokio::spawn(async move {
        let (mut inbox, mut out) = delivery;

        let mut state = PartyState { aux_info: None };

        while let Some(cmd) = rx.recv().await {
            match cmd {
                PartyCommand::RunAuxInfo { reply } => {
                    println!(
                        "[party {party_id}] received RunAuxInfo command - starting primes generation"
                    );
                    let execution_id = ExecutionId::new(b"aux-info-demo");
                    let primes = PregeneratedPrimes::generate(&mut OsRng);

                    // Build a connected party using the long-lived endpoints
                    let mpc_party = MpcParty::connected((&mut inbox, &mut out));

                    let result: anyhow::Result<()> = async {
                        println!("[party {party_id}] starting aux_info_gen");

                        let generated_aux_info =
                            cggmp24::aux_info_gen(execution_id, party_id, n, primes)
                                .start(&mut OsRng, mpc_party)
                                .await
                                .map_err(anyhow::Error::from)?;

                        println!("[party {party_id}] aux_info_gen finished successfully");

                        state.aux_info = Some(generated_aux_info);
                        Ok(())
                    }
                    .await;

                    if let Err(e) = &result {
                        println!("[party {party_id}] aux-info failed: {e}");
                    }

                    let _ = reply.send(result);
                }

                PartyCommand::Shutdown => break,
            }
        }
    });

    PartyHandle { id: party_id, tx }
}

async fn broadcast_run_aux_info(handles: &[PartyHandle]) -> anyhow::Result<()> {
    let rxs = handles.iter().map(|h| {
        let (reply_tx, reply_rx) = oneshot::channel();
        h.tx.send(PartyCommand::RunAuxInfo { reply: reply_tx })
            .unwrap();
        reply_rx
    });

    let per_party: Vec<anyhow::Result<()>> = try_join_all(rxs).await?;

    for (i, r) in per_party.into_iter().enumerate() {
        r.map_err(|e| anyhow::anyhow!("party {} aux-info failed: {e}", handles[i].id))?;
    }

    println!("Aux-Info finished ({} parties).", handles.len());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let n: u16 = 3;

    let deliveries = make_memory_deliveries(n);

    let handles: Vec<_> = (0..n)
        .zip(deliveries.into_iter())
        .map(|(party_id, delivery)| spawn_party(party_id, n, delivery))
        .collect();

    broadcast_run_aux_info(&handles).await?;

    for h in &handles {
        let _ = h.tx.send(PartyCommand::Shutdown);
    }

    Ok(())
}
