use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::net::Ipv4Addr;
use std::time::SystemTime;

/// L3/L4 protocols this IDS currently understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4Protocol {
    Icmp,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

/// Normalized view of a single captured packet, independent of the
/// capture backend (pcap today, potentially an inline NFQUEUE-style
/// backend for IPS mode later).
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub captured_at: SystemTime,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub ttl: u8,
    pub total_len: u16,
    pub protocol: L4Protocol,
    /// 0 for ICMP.
    pub src_port: u16,
    /// 0 for ICMP.
    pub dst_port: u16,
    /// 0 for TCP/UDP.
    pub icmp_type: u8,
    /// 0 for TCP/UDP.
    pub icmp_code: u8,
    /// Default for ICMP/UDP.
    pub tcp_flags: TcpFlags,
    /// 0 for ICMP/UDP.
    pub window_size: u16,
    pub payload: Vec<u8>,
    pub payload_len: usize,
}

/// Parses an Ethernet frame down to ICMPv4/TCP/UDP over IPv4.
/// Anything else (IPv6, ARP, ICMPv6, ...) is intentionally out of scope for now.
pub fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
    let sliced = match SlicedPacket::from_ethernet(data) {
        Ok(sliced) => sliced,
        Err(e) => {
            eprintln!("Failed to parse packet: {:?}", e);
            return None;
        }
    };

    let NetSlice::Ipv4(ipv4) = sliced.net? else {
        return None;
    };
    let header = ipv4.header();

    let base = PacketInfo {
        captured_at: SystemTime::now(),
        src_ip: header.source_addr(),
        dst_ip: header.destination_addr(),
        ttl: header.ttl(),
        total_len: header.total_len(),
        protocol: L4Protocol::Icmp,
        src_port: 0,
        dst_port: 0,
        icmp_type: 0,
        icmp_code: 0,
        tcp_flags: TcpFlags::default(),
        window_size: 0,
        payload: Vec::new(),
        payload_len: 0,
    };

    match sliced.transport? {
        TransportSlice::Icmpv4(icmp) => Some(PacketInfo {
            protocol: L4Protocol::Icmp,
            icmp_type: icmp.type_u8(),
            icmp_code: icmp.code_u8(),
            payload_len: icmp.payload().len(),
            payload: icmp.payload().to_vec(),
            ..base
        }),
        TransportSlice::Tcp(tcp) => Some(PacketInfo {
            protocol: L4Protocol::Tcp,
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
            tcp_flags: TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
                psh: tcp.psh(),
                urg: tcp.urg(),
            },
            window_size: tcp.window_size(),
            payload_len: tcp.payload().len(),
            payload: tcp.payload().to_vec(),
            ..base
        }),
        TransportSlice::Udp(udp) => Some(PacketInfo {
            protocol: L4Protocol::Udp,
            src_port: udp.source_port(),
            dst_port: udp.destination_port(),
            payload_len: udp.payload().len(),
            payload: udp.payload().to_vec(),
            ..base
        }),
        // ICMPv6 rides on IPv6, which can't reach this branch since we
        // already matched on NetSlice::Ipv4 above.
        TransportSlice::Icmpv6(_) => None,
    }
}
