mod action;
mod dataset;
mod detector;
mod features;
mod flow;
mod ml;
mod packet;

use action::Mode;
use dataset::DatasetWriter;
use detector::Detector;
use features::FeatureVector;
use flow::{FlowKey, FlowTracker};
use ml::MlEngine;
use pcap::{Activated, Capture, Device};
use std::env;

const DATASET_PATH: &str = "dataset.csv";

/// Either a live device capture or a previously-recorded pcap file, unified
/// behind `Capture<dyn Activated>` so the analysis loop below doesn't need
/// to care which one it's reading from.
fn open_capture(pcap_file: Option<&str>) -> Capture<dyn Activated> {
    match pcap_file {
        Some(path) => {
            println!("Replaying pcap file: {}", path);
            Capture::from_file(path)
                .expect("Failed to open pcap file")
                .into()
        }
        None => {
            let device = Device::lookup().unwrap().unwrap();
            println!("Chosen device: {}", device.name);
            Capture::from_device(device)
                .expect("Failed to open device")
                .promisc(true)
                .open()
                .expect("Failed to activate device")
                .into()
        }
    }
}

fn main() {
    // Usage: traffic_analyzer [path/to/capture.pcap]
    // With no argument, capture live from the default device; with a path,
    // replay that pcap file through the same parsing/detection pipeline.
    let pcap_file = env::args().nth(1);
    let mut cap = open_capture(pcap_file.as_deref());

    let mut flow_tracker = FlowTracker::new();
    let mut detector = Detector::new();

    // Class labels the (currently untrained) classifier reports against.
    // These are protocol-level DDoS/scan anomaly classes - signature-based
    // detections like FTP anonymous login stay in `detector.rs`, since the
    // FeatureVector has no payload-content signal for the ML model to
    // learn that from. tcp_syn_anomaly is split out from tcp_anomaly
    // because a SYN flood/scan (half-open connections) is behaviorally
    // distinct from a full TCP flood. Random weights -> verdicts below are
    // not meaningful yet; see ml::MlEngine and README for how a trained
    // model would be plugged in.
    let ml_engine = MlEngine::new_untrained(
        [
            "benign",
            "tcp_anomaly",
            "tcp_syn_anomaly",
            "udp_anomaly",
            "icmp_anomaly",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    );
    println!("ML model is untrained (random weights) - verdicts below are illustrative only.");

    let mut dataset_writer =
        DatasetWriter::create(DATASET_PATH).expect("Failed to create dataset file");

    // pcap is a passive tap: IDS mode is the only one that can actually be
    // enforced today. Mode::Ips becomes meaningful once an inline capture
    // backend (see action::Mode) replaces pcap.
    let mode = Mode::Ids;

    while let Ok(raw_packet) = cap.next_packet() {
        let Some(parsed) = packet::parse_packet(raw_packet.data) else {
            continue;
        };

        let flow_key = FlowKey::from_packet(&parsed);
        let flow_state = flow_tracker.observe(&parsed);
        let feature_vector = FeatureVector::from_packet(&parsed, &flow_state);

        if let Err(e) = dataset_writer.write_sample(
            parsed.captured_at,
            parsed.src_ip,
            parsed.dst_ip,
            &feature_vector,
            "unknown",
        ) {
            eprintln!("Failed to write dataset sample: {}", e);
        }

        let verdict = ml_engine.predict(&feature_vector);
        let ml_action = action::decide(&verdict.label, verdict.confidence, mode);
        if verdict.label != "benign" {
            println!(
                "[ml:untrained] {:?} {} -> {} ({:.2}) action={:?}",
                parsed.protocol, parsed.src_ip, verdict.label, verdict.confidence, ml_action
            );
        }

        for alert in detector.observe_packet(&parsed, flow_key) {
            println!("[rule] {:?}", alert);
        }
        for alert in detector.scan_half_open_tcp(flow_tracker.flows()) {
            println!("[rule] {:?}", alert);
        }
    }

    let _ = dataset_writer.flush();
}
