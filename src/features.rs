use crate::flow::FlowState;
use crate::packet::{L4Protocol, PacketInfo};

/// Flat numeric representation of a packet (+ its flow context), ready to
/// be fed straight into an ML model's input tensor. Keeping this as a
/// fixed-size array of f32 means the parsing layer and the ML layer only
/// need to agree on `FeatureVector::LEN` and `FIELD_NAMES`.
#[derive(Debug, Clone, Copy)]
pub struct FeatureVector {
    pub protocol_icmp: f32,
    pub protocol_tcp: f32,
    pub protocol_udp: f32,
    pub total_len: f32,
    pub ttl: f32,
    pub src_port: f32,
    pub dst_port: f32,
    pub payload_len: f32,
    pub tcp_syn: f32,
    pub tcp_ack: f32,
    pub tcp_fin: f32,
    pub tcp_rst: f32,
    pub tcp_psh: f32,
    pub tcp_urg: f32,
    pub window_size: f32,
    pub flow_packet_count: f32,
    pub flow_byte_count: f32,
    pub flow_duration_secs: f32,
    pub flow_packets_per_sec: f32,
}

impl FeatureVector {
    pub const LEN: usize = 19;

    pub const FIELD_NAMES: [&'static str; Self::LEN] = [
        "protocol_icmp",
        "protocol_tcp",
        "protocol_udp",
        "total_len",
        "ttl",
        "src_port",
        "dst_port",
        "payload_len",
        "tcp_syn",
        "tcp_ack",
        "tcp_fin",
        "tcp_rst",
        "tcp_psh",
        "tcp_urg",
        "window_size",
        "flow_packet_count",
        "flow_byte_count",
        "flow_duration_secs",
        "flow_packets_per_sec",
    ];

    pub fn from_packet(packet: &PacketInfo, flow: &FlowState) -> Self {
        FeatureVector {
            protocol_icmp: (packet.protocol == L4Protocol::Icmp) as u32 as f32,
            protocol_tcp: (packet.protocol == L4Protocol::Tcp) as u32 as f32,
            protocol_udp: (packet.protocol == L4Protocol::Udp) as u32 as f32,
            total_len: packet.total_len as f32,
            ttl: packet.ttl as f32,
            src_port: packet.src_port as f32,
            dst_port: packet.dst_port as f32,
            payload_len: packet.payload_len as f32,
            tcp_syn: packet.tcp_flags.syn as u32 as f32,
            tcp_ack: packet.tcp_flags.ack as u32 as f32,
            tcp_fin: packet.tcp_flags.fin as u32 as f32,
            tcp_rst: packet.tcp_flags.rst as u32 as f32,
            tcp_psh: packet.tcp_flags.psh as u32 as f32,
            tcp_urg: packet.tcp_flags.urg as u32 as f32,
            window_size: packet.window_size as f32,
            flow_packet_count: flow.packet_count as f32,
            flow_byte_count: flow.byte_count as f32,
            flow_duration_secs: flow.duration().as_secs_f32(),
            flow_packets_per_sec: flow.packets_per_sec(),
        }
    }

    pub fn to_array(&self) -> [f32; Self::LEN] {
        [
            self.protocol_icmp,
            self.protocol_tcp,
            self.protocol_udp,
            self.total_len,
            self.ttl,
            self.src_port,
            self.dst_port,
            self.payload_len,
            self.tcp_syn,
            self.tcp_ack,
            self.tcp_fin,
            self.tcp_rst,
            self.tcp_psh,
            self.tcp_urg,
            self.window_size,
            self.flow_packet_count,
            self.flow_byte_count,
            self.flow_duration_secs,
            self.flow_packets_per_sec,
        ]
    }
}
