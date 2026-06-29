use crate::packet::{L4Protocol, PacketInfo};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

/// Identifies a unidirectional flow. ICMP flows have port 0 on both ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: L4Protocol,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

impl FlowKey {
    pub fn from_packet(packet: &PacketInfo) -> Self {
        FlowKey {
            protocol: packet.protocol,
            src_ip: packet.src_ip,
            src_port: packet.src_port,
            dst_ip: packet.dst_ip,
            dst_port: packet.dst_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowState {
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub seen_syn: bool,
    pub seen_ack: bool,
    pub seen_fin: bool,
}

impl FlowState {
    fn new(packet: &PacketInfo) -> Self {
        FlowState {
            packet_count: 0,
            byte_count: 0,
            first_seen: packet.captured_at,
            last_seen: packet.captured_at,
            seen_syn: false,
            seen_ack: false,
            seen_fin: false,
        }
    }

    pub fn duration(&self) -> Duration {
        self.last_seen
            .duration_since(self.first_seen)
            .unwrap_or_default()
    }

    /// Wall-clock time since the flow started, regardless of when the last
    /// packet arrived. Used to spot half-open connections that the peer
    /// never completed (the flow stops getting new packets, but is still
    /// "open" from the attacker's point of view) - a plain `duration()`
    /// based on `last_seen` would never grow once packets stop arriving.
    pub fn age(&self) -> Duration {
        SystemTime::now()
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

    fn update(&mut self, packet: &PacketInfo) {
        self.packet_count += 1;
        self.byte_count += packet.total_len as u64;
        self.last_seen = packet.captured_at;
        if packet.protocol == L4Protocol::Tcp {
            self.seen_syn |= packet.tcp_flags.syn;
            self.seen_ack |= packet.tcp_flags.ack;
            self.seen_fin |= packet.tcp_flags.fin;
        }
    }
}

/// Tracks per-flow state across the lifetime of the capture.
///
/// This is intentionally simple (unidirectional, in-memory, never expired).
/// Good enough for IDS-style passive monitoring; a production deployment
/// would want flow timeouts/eviction, which is not needed yet.
#[derive(Default)]
pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the packet against its flow and returns a snapshot of the
    /// updated flow state, for immediate use by detectors/feature extraction.
    pub fn observe(&mut self, packet: &PacketInfo) -> FlowState {
        let key = FlowKey::from_packet(packet);
        let state = self
            .flows
            .entry(key)
            .or_insert_with(|| FlowState::new(packet));
        state.update(packet);
        state.clone()
    }

    pub fn flows(&self) -> &HashMap<FlowKey, FlowState> {
        &self.flows
    }
}
