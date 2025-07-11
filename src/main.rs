use etherparse::{SlicedPacket, TransportSlice};
use memchr::memmem::Finder;
use pcap::{Capture, Device};
use std::cmp::max;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

fn main() {
    let device = Device::lookup().unwrap().unwrap();

    println!("Choosed device: {}", device.name);

    let mut cap = Capture::from_device(device)
        .expect("Failed to open device")
        .promisc(true)
        .open()
        .expect("Failed to activate device");

    let mut tcp_streams: HashMap<
        (String, u16, String, u16),
        (bool, bool, bool, SystemTime, SystemTime),
    > = HashMap::new(); // Key: (src_ip, src_port, dst_ip, dst_port), Value: (ack, syn, fin, start_time, end_time)

    let mut icmp_statistics: HashMap<(String, String, u8), (u16, bool)> = HashMap::new(); // (src_ip, dst_ip, icmp type), (count, notified)
    let mut syn_statistics: HashMap<(String, String), (u16, bool)> = HashMap::new(); // (src_ip, dst_ip), (count, notified)
    let mut ftp_logins: HashMap<(String, u16, String, u16), (bool, bool, bool)> = HashMap::new(); // Key: (src_ip, src_port, dst_ip, dst_port), (anon_login, anon_pass, notified)

    while let Ok(packet) = cap.next_packet() {
        if let Some((key, params, payload)) = parse_tcp_packet(packet.data) {
            // Append the payload to the corresponding TCP stream
            tcp_streams
                .entry(key.clone())
                .or_insert_with(|| (false, false, false, SystemTime::now(), SystemTime::now()));
            if let Some(v) = tcp_streams.get_mut(&key) {
                v.0 |= max(params.0, v.0); // Update ack
                v.1 |= max(params.1, v.1); // Update syn
                v.2 |= max(params.2, v.2); // Update fin
                v.3 = v.3; // Update start time
                v.4 = max(v.4, SystemTime::now()); // Update end time
            }
            if let Some((anon_login_ftp, anon_pass_ftp)) = parse_ftp_packet(payload.clone()) {
                if anon_login_ftp || anon_pass_ftp {
                    ftp_logins
                        .entry(key.clone())
                        .or_insert_with(|| (false, false, false));
                    if let Some(v) = ftp_logins.get_mut(&key) {
                        v.0 |= max(anon_login_ftp, v.0); // Update ack
                        v.1 |= max(anon_pass_ftp, v.1); // Update syn
                    }
                }
            }
        }
        if let Some((key, _)) = parse_icmp_packet(packet.data) {
            icmp_statistics
                .entry(key.clone())
                .or_insert_with(|| (0, false));

            if let Some(v) = icmp_statistics.get_mut(&key) {
                v.0 += 1;
                if v.0 > 10 && key.2 == 3 && !v.1 {
                    println!("Possible UDP scan detected: {:?}", key);
                    v.1 = true
                }
            }
        }

        for (key, value) in ftp_logins.iter_mut() {
            // let (src_ip, src_port, dst_ip, dst_port) = key;
            let (anon_login, anon_pass, notified) = value;

            if *anon_login && *anon_pass {
                if !*notified {
                    println!("Ftp anonymous login: {:?}", key);
                    *notified = true;
                }
            }
        }

        for (key, value) in detect_syn_ack_scanning(&tcp_streams) {
            syn_statistics
                .entry(key.clone())
                .or_insert_with(|| (1, false));
            if let Some(v) = syn_statistics.get_mut(&key) {
                v.0 = value;
            }
        }

        for (key, value) in syn_statistics.iter_mut() {
            if (*value).0 > 100 && !(*value).1 {
                println!(
                    "Potentional SYN scan or SYN dos: {:?} packets: {}",
                    key,
                    (*value).0
                );
                (*value).1 = true;
            }
        }
    }
}

fn parse_ftp_packet(data: Vec<u8>) -> Option<(bool, bool)> {
    let anon_login_bytes: [u8; 16] = [
        0x55, 0x53, 0x45, 0x52, 0x20, 0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73, 0x0d,
        0x0a,
    ]; // Message: USER Anonymous

    let anon_pass_bytes: [u8; 16] = [
        0x50, 0x41, 0x53, 0x53, 0x20, 0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73, 0x0d,
        0x0a,
    ]; // Message: PASS Anonymous

    return Some((
        !Finder::new(&anon_login_bytes).find(&data).is_none(),
        !Finder::new(&anon_pass_bytes).find(&data).is_none(),
    ));
}

fn parse_icmp_packet(data: &[u8]) -> Option<((String, String, u8), Vec<u8>)> {
    match SlicedPacket::from_ethernet(data) {
        Ok(sliced) => {
            if let (Some(etherparse::NetSlice::Ipv4(ipv4)), Some(TransportSlice::Icmpv4(icmp))) =
                (sliced.net, sliced.transport)
            {
                let src_ip = ipv4.header().source_addr().to_string();
                let dst_ip = ipv4.header().destination_addr().to_string();
                let icmp_type = icmp.type_u8();
                let payload = icmp.payload().to_vec();

                return Some(((src_ip, dst_ip, icmp_type), (payload)));
            }
        }
        Err(e) => eprintln!("Failed to parse packet: {:?}", e),
    }
    None
}

fn parse_tcp_packet(
    data: &[u8],
) -> Option<((String, u16, String, u16), (bool, bool, bool), Vec<u8>)> {
    match SlicedPacket::from_ethernet(data) {
        Ok(sliced) => {
            if let (Some(etherparse::NetSlice::Ipv4(ipv4)), Some(TransportSlice::Tcp(tcp))) =
                (sliced.net, sliced.transport)
            {
                let src_ip = ipv4.header().source_addr().to_string();
                let dst_ip = ipv4.header().destination_addr().to_string();
                let src_port = tcp.source_port();
                let dst_port = tcp.destination_port();
                let ack = tcp.ack();
                let syn = tcp.syn();
                let fin = tcp.fin();

                let payload = tcp.payload().to_vec();

                return Some((
                    (src_ip, src_port, dst_ip, dst_port),
                    (ack, syn, fin),
                    (payload),
                ));
            }
        }
        Err(e) => eprintln!("Failed to parse packet: {:?}", e),
    }
    None
}

fn detect_syn_ack_scanning(
    tcp_streams: &HashMap<(String, u16, String, u16), (bool, bool, bool, SystemTime, SystemTime)>,
) -> Vec<((String, String), u16)> {
    let mut syn_statistics: HashMap<(String, String), u16> = HashMap::new();
    for (key, value) in tcp_streams.iter() {
        let (from_address, _, to_address, _) = key;
        let (_, syn, fin, start_time, _) = value;

        if *syn
            && !*fin
            && (SystemTime::now().duration_since(*start_time).unwrap() > Duration::from_secs(3))
        {
            syn_statistics
                .entry((from_address.clone(), to_address.clone()))
                .and_modify(|tcp_count| *tcp_count += 1)
                .or_insert(1);
        }
    }

    return Vec::from_iter(syn_statistics.iter().map(|(k, v)| (k.clone(), *v)));
}
