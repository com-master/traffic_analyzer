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
use pcap::{Capture, Device};

const DATASET_PATH: &str = "dataset.csv";

fn main() {
    let device = Device::lookup().unwrap().unwrap();
    println!("Chosen device: {}", device.name);

    let mut cap = Capture::from_device(device)
        .expect("Failed to open device")
        .promisc(true)
        .open()
        .expect("Failed to activate device");

    let mut flow_tracker = FlowTracker::new();
    let mut detector = Detector::new();

    // Class labels the (currently untrained) classifier reports against.
    // Random weights -> verdicts below are not meaningful yet; see
    // ml::MlEngine and README for how a trained model would be plugged in.
    let ml_engine = MlEngine::new_untrained(
        ["benign", "syn_scan", "udp_scan", "ftp_anon_login"]
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
