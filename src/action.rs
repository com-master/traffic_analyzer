/// Operating mode for the analyzer.
///
/// Only `Ids` is actually enforced today: the capture backend is `pcap`,
/// which only observes a copy of the traffic, so there is nothing to
/// block. `Ips` is the extension point for once an inline backend (e.g.
/// an NFQUEUE-based capture/verdict loop) replaces pcap and packets can
/// actually be dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Ids,
    Ips,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
}

const BLOCK_CONFIDENCE_THRESHOLD: f32 = 0.9;

/// Decides what to do about a packet given its ML verdict.
///
/// In `Mode::Ids` this always returns `Allow` - the decision is logged for
/// visibility but never enforced. In `Mode::Ips` it returns `Block` for a
/// confident non-benign verdict; wiring that decision up to an actual
/// inline capture backend is future work.
pub fn decide(verdict_label: &str, confidence: f32, mode: Mode) -> Action {
    match mode {
        Mode::Ids => Action::Allow,
        Mode::Ips => {
            if verdict_label != "benign" && confidence >= BLOCK_CONFIDENCE_THRESHOLD {
                Action::Block
            } else {
                Action::Allow
            }
        }
    }
}
