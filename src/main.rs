use pcap::{Activated, Capture, Device};
use std::env;
use traffic_analyzer::action::{self, Mode};
use traffic_analyzer::dataset::DatasetWriter;
use traffic_analyzer::detector::Detector;
use traffic_analyzer::features::FeatureVector;
use traffic_analyzer::flow::{FlowKey, FlowTracker};
use traffic_analyzer::host::HostTracker;
use traffic_analyzer::ml::MlEngine;
use traffic_analyzer::packet;

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
    // Usage: traffic_analyzer [path/to/capture.pcap] [--weights path/to/weights.bin]
    // With no pcap path, capture live from the default device; with a path,
    // replay that pcap file through the same parsing/detection pipeline.
    // --weights loads a model trained by the `train` binary instead of
    // random weights.
    let args: Vec<String> = env::args().collect();
    let mut pcap_file = None;
    let mut weights_path = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--weights" => {
                i += 1;
                weights_path = args.get(i).cloned();
            }
            other => pcap_file = Some(other.to_string()),
        }
        i += 1;
    }
    let mut cap = open_capture(pcap_file.as_deref());

    let mut flow_tracker = FlowTracker::new();
    let mut host_tracker = HostTracker::new();
    let mut detector = Detector::new();

    // Class labels the classifier reports against - protocol-level
    // DDoS/scan anomaly classes. Signature-based detections like FTP
    // anonymous login stay in `detector.rs`, since the FeatureVector has no
    // payload-content signal for the ML model to learn that from.
    // tcp_syn_anomaly is split out from tcp_anomaly because a SYN
    // flood/scan (half-open connections) is behaviorally distinct from a
    // full TCP flood. Order must match the labels `train` was run with.
    let labels: Vec<String> = [
        "benign",
        "tcp_anomaly",
        "tcp_syn_anomaly",
        "udp_anomaly",
        "icmp_anomaly",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let (ml_engine, ml_log_tag) = match weights_path {
        Some(path) => {
            println!("Loading trained model weights from {}", path);
            (
                MlEngine::load(&path, labels).expect("Failed to load model weights"),
                "ml",
            )
        }
        None => {
            println!(
                "ML model is untrained (random weights) - verdicts below are illustrative only. \
                 Pass --weights path/to/weights.bin to load a trained model (see `train`)."
            );
            (MlEngine::new_untrained(labels), "ml:untrained")
        }
    };

    let mut dataset_writer =
        DatasetWriter::create(DATASET_PATH).expect("Failed to create dataset file");

    // pcap is a passive tap: IDS mode is the only one that can actually be
    // enforced today. Mode::Ips becomes meaningful once an inline capture
    // backend (see action::Mode) replaces pcap.
    let mode = Mode::Ids;

    while let Ok(raw_packet) = cap.next_packet() {
        let captured_at = std::time::UNIX_EPOCH
            + std::time::Duration::new(
                raw_packet.header.ts.tv_sec as u64,
                raw_packet.header.ts.tv_usec as u32 * 1000,
            );
        let Some(parsed) = packet::parse_packet(raw_packet.data, captured_at) else {
            continue;
        };

        let flow_key = FlowKey::from_packet(&parsed);
        let flow_state = flow_tracker.observe(&parsed);
        let host_state = host_tracker.observe(&parsed);
        let feature_vector = FeatureVector::from_packet(&parsed, &flow_state, &host_state);

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
                "[{}] {:?} {} -> {} ({:.2}) action={:?}",
                ml_log_tag, parsed.protocol, parsed.src_ip, verdict.label, verdict.confidence, ml_action
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
