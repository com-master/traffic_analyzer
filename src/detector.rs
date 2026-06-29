use crate::flow::{FlowKey, FlowState};
use crate::packet::{L4Protocol, PacketInfo};
use memchr::memmem::Finder;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Alerts raised by the rule-based heuristics. These run independently of
/// the ML verdict (`crate::ml`) so the IDS still catches known patterns
/// even before a trained model is available.
#[derive(Debug, Clone)]
pub enum Alert {
    FtpAnonymousLogin {
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    },
    SynScan {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        half_open_count: u32,
    },
    UdpPortScan {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        unreachable_count: u32,
    },
}

const FTP_ANON_USER: &[u8] = b"USER Anonymous\r\n";
const FTP_ANON_PASS: &[u8] = b"PASS Anonymous\r\n";
const SYN_HALF_OPEN_AGE: Duration = Duration::from_secs(3);
const SYN_SCAN_THRESHOLD: u32 = 100;
const UDP_SCAN_THRESHOLD: u32 = 10;

#[derive(Default)]
struct FtpLoginState {
    saw_user: bool,
    saw_pass: bool,
    notified: bool,
}

#[derive(Default)]
struct IcmpUnreachableState {
    count: u32,
    notified: bool,
}

#[derive(Default)]
struct SynScanState {
    notified: bool,
}

/// Rule-based heuristics: FTP anonymous login, TCP SYN scan/DoS, UDP port
/// scan (inferred from ICMP "destination unreachable" replies).
#[derive(Default)]
pub struct Detector {
    ftp_logins: HashMap<FlowKey, FtpLoginState>,
    icmp_unreachable: HashMap<(Ipv4Addr, Ipv4Addr), IcmpUnreachableState>,
    syn_scans: HashMap<(Ipv4Addr, Ipv4Addr), SynScanState>,
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Per-packet checks: FTP anonymous login and ICMP-unreachable counting.
    pub fn observe_packet(&mut self, packet: &PacketInfo, flow_key: FlowKey) -> Vec<Alert> {
        let mut alerts = Vec::new();
        match packet.protocol {
            L4Protocol::Tcp => self.observe_ftp(packet, flow_key, &mut alerts),
            L4Protocol::Icmp => self.observe_icmp_unreachable(packet, &mut alerts),
            L4Protocol::Udp => {}
        }
        alerts
    }

    fn observe_ftp(&mut self, packet: &PacketInfo, flow_key: FlowKey, alerts: &mut Vec<Alert>) {
        let saw_user = Finder::new(FTP_ANON_USER).find(&packet.payload).is_some();
        let saw_pass = Finder::new(FTP_ANON_PASS).find(&packet.payload).is_some();
        if !saw_user && !saw_pass {
            return;
        }

        let state = self.ftp_logins.entry(flow_key).or_default();
        state.saw_user |= saw_user;
        state.saw_pass |= saw_pass;

        if state.saw_user && state.saw_pass && !state.notified {
            state.notified = true;
            alerts.push(Alert::FtpAnonymousLogin {
                src_ip: packet.src_ip,
                src_port: packet.src_port,
                dst_ip: packet.dst_ip,
                dst_port: packet.dst_port,
            });
        }
    }

    fn observe_icmp_unreachable(&mut self, packet: &PacketInfo, alerts: &mut Vec<Alert>) {
        // ICMP type 3 = Destination Unreachable. A burst of these from a
        // single host is a common side effect of a UDP port scan.
        if packet.icmp_type != 3 {
            return;
        }

        let state = self
            .icmp_unreachable
            .entry((packet.src_ip, packet.dst_ip))
            .or_default();
        state.count += 1;

        if state.count > UDP_SCAN_THRESHOLD && !state.notified {
            state.notified = true;
            alerts.push(Alert::UdpPortScan {
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                unreachable_count: state.count,
            });
        }
    }

    /// Whole-table check: counts, per (src, dst) pair, how many TCP flows
    /// are stuck half-open (SYN seen, no FIN, open for more than
    /// `SYN_HALF_OPEN_AGE`). Meant to be called periodically against the
    /// live flow table, not once per packet.
    pub fn scan_half_open_tcp(&mut self, flows: &HashMap<FlowKey, FlowState>) -> Vec<Alert> {
        let mut half_open_counts: HashMap<(Ipv4Addr, Ipv4Addr), u32> = HashMap::new();

        for (key, flow) in flows.iter() {
            if key.protocol != L4Protocol::Tcp {
                continue;
            }
            let stuck_half_open =
                flow.seen_syn && !flow.seen_fin && flow.age() > SYN_HALF_OPEN_AGE;
            if stuck_half_open {
                *half_open_counts
                    .entry((key.src_ip, key.dst_ip))
                    .or_insert(0) += 1;
            }
        }

        let mut alerts = Vec::new();
        for (pair, count) in half_open_counts {
            let state = self.syn_scans.entry(pair).or_default();
            if count > SYN_SCAN_THRESHOLD && !state.notified {
                state.notified = true;
                alerts.push(Alert::SynScan {
                    src_ip: pair.0,
                    dst_ip: pair.1,
                    half_open_count: count,
                });
            }
        }
        alerts
    }
}
