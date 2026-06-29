use crate::packet::{L4Protocol, PacketInfo};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

/// Tracks a source IP's traffic across all protocols/destinations combined,
/// the way `FlowTracker` tracks a single 5-tuple flow.
///
/// A single attacker can split a DDoS across protocols (e.g. an ICMP flood
/// and a TCP SYN flood at once) so that each individual flow's rate looks
/// unremarkable on its own. Scoped by `src_ip` rather than `dst_ip` so a
/// verdict derived from this can be enforced (in a future IPS mode) by
/// blocking the actual attacker, instead of collaterally blocking all
/// traffic to the target.
#[derive(Debug, Clone)]
pub struct HostState {
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub icmp_count: u64,
    pub tcp_count: u64,
    pub udp_count: u64,
}

impl HostState {
    fn new(packet: &PacketInfo) -> Self {
        HostState {
            packet_count: 0,
            byte_count: 0,
            first_seen: packet.captured_at,
            last_seen: packet.captured_at,
            icmp_count: 0,
            tcp_count: 0,
            udp_count: 0,
        }
    }

    pub fn duration(&self) -> Duration {
        self.last_seen
            .duration_since(self.first_seen)
            .unwrap_or_default()
    }

    pub fn packets_per_sec(&self) -> f32 {
        let secs = self.duration().as_secs_f32();
        if secs > 0.0 {
            self.packet_count as f32 / secs
        } else {
            self.packet_count as f32
        }
    }

    /// How many distinct protocols (0-3) this source has sent so far - the
    /// fingerprint of a multi-vector attack (e.g. ICMP + TCP at once), as
    /// opposed to a high rate concentrated in a single protocol.
    pub fn protocol_diversity(&self) -> u32 {
        [self.icmp_count, self.tcp_count, self.udp_count]
            .iter()
            .filter(|&&count| count > 0)
            .count() as u32
    }

    fn update(&mut self, packet: &PacketInfo) {
        self.packet_count += 1;
        self.byte_count += packet.total_len as u64;
        self.last_seen = packet.captured_at;
        match packet.protocol {
            L4Protocol::Icmp => self.icmp_count += 1,
            L4Protocol::Tcp => self.tcp_count += 1,
            L4Protocol::Udp => self.udp_count += 1,
        }
    }
}

/// Tracks per-source-IP state across the lifetime of the capture, combining
/// all protocols and destinations. Same caveats as `FlowTracker`: in-memory,
/// never expired/evicted - acceptable for this iteration.
#[derive(Default)]
pub struct HostTracker {
    hosts: HashMap<Ipv4Addr, HostState>,
}

impl HostTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the packet against its source host and returns a snapshot of
    /// the updated state, for immediate use by feature extraction.
    pub fn observe(&mut self, packet: &PacketInfo) -> HostState {
        let state = self
            .hosts
            .entry(packet.src_ip)
            .or_insert_with(|| HostState::new(packet));
        state.update(packet);
        state.clone()
    }
}
