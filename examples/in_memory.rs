use round_based::{MessageDestination, MessageType, MsgId, Outgoing, PartyIndex};
use std::fmt::Debug;

/// Resolve MessageDestination -> concrete recipient IDs (excluding self for AllParties).
fn resolve_recipients(me: PartyIndex, n: PartyIndex, dest: MessageDestination) -> Vec<PartyIndex> {
    match dest {
        MessageDestination::OneParty(pid) => vec![pid],
        MessageDestination::AllParties => (0..n).filter(|&pid| pid != me).collect(),
    }
}

/// Dry-run router that *logs* deliveries and mints MsgId as a per-sender counter.
struct DryRouter {
    n: PartyIndex,
    next_id_by_sender: Vec<MsgId>, // next_id_by_sender[pid] = next MsgId to use
}

impl DryRouter {
    fn new(n: PartyIndex) -> Self {
        Self {
            n,
            next_id_by_sender: vec![0; n as usize],
        }
    }

    /// Allocate a new MsgId for `sender` (monotonic per sender, resets per session).
    fn next_msg_id(&mut self, sender: PartyIndex) -> MsgId {
        let id_ref = &mut self.next_id_by_sender[sender as usize];
        let id = *id_ref;
        *id_ref += 1;
        id
    }

    /// Pretend-deliver one Outgoing<M> emitted by `sender`: print what Incoming would look like.
    fn deliver<M: Debug>(&mut self, sender: PartyIndex, out: Outgoing<M>) {
        let sender_msg_id: MsgId = self.next_msg_id(sender);
        let msg_type = match out.recipient {
            MessageDestination::AllParties => MessageType::Broadcast,
            MessageDestination::OneParty(_) => MessageType::P2P,
        };
        let recips = resolve_recipients(sender, self.n, out.recipient);

        for to in recips {
            println!(
                "Incoming {{ id: {sender_msg_id}, sender: {sender}, msg_type: {:?}, to: {to}, msg: {:?} }}",
                msg_type, out.msg
            );
        }
        println!();
    }
}

// --- tiny demo ---
fn main() {
    let n: PartyIndex = 4; // parties 0,1,2,3
    let mut router = DryRouter::new(n);

    // party 1 broadcasts once -> same MsgId for all recipients (0,2,3)
    router.deliver(
        1,
        Outgoing {
            recipient: MessageDestination::AllParties,
            msg: "hello all",
        },
    );

    // party 1 broadcasts again -> new MsgId for all recipients (0,2,3)
    router.deliver(
        1,
        Outgoing {
            recipient: MessageDestination::AllParties,
            msg: "hello all",
        },
    );

    // party 2 sends a P2P message to party 3 -> one Incoming at 3
    router.deliver(
        2,
        Outgoing {
            recipient: MessageDestination::OneParty(3),
            msg: "hi 3",
        },
    );
}
