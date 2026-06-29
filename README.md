# Traffic analyzer

Live network IDS written in Rust. Captures traffic with `pcap` — either
live from a network device or replayed from a `.pcap` file — parses
ICMP/TCP/UDP over IPv4, and raises alerts from two independent sources:

- **Rule-based detector** (`src/detector.rs`): FTP anonymous login, TCP SYN
  scan/DoS (stuck half-open connections), UDP port scan (inferred from ICMP
  "destination unreachable" bursts).
- **ML classifier** (`src/ml`): a small feed-forward network (via the
  [`burn`](https://burn.dev) framework, pure Rust) that scores each packet
  against the same flow/packet features. **Currently runs with random,
  untrained weights** — its verdicts are illustrative only, showing that the
  capture → features → tensor → verdict pipeline is wired end-to-end. See
  "Training a model" below for how to make it meaningful.

## Pipeline

```
pcap capture -> packet::parse_packet -> flow::FlowTracker -> features::FeatureVector
                                                                    |
                                                  +-----------------+------------------+
                                                  |                                    |
                                          dataset::DatasetWriter              ml::MlEngine::predict
                                          (dataset.csv, label="unknown")              |
                                                                              action::decide (Mode::Ids/Ips)
```

Every observed packet is turned into a fixed-size feature vector
(`FeatureVector`, see `src/features.rs`) combining per-packet header fields
(protocol, length, TTL, ports, TCP flags, window size, payload length) with
flow-level aggregates (packet/byte counts, duration, packets/sec). Each
sample is appended to `dataset.csv` for offline labeling/training, and also
fed straight into the ML classifier for a live verdict.

## IDS vs IPS

`pcap` is a passive tap: it only sees a copy of traffic and cannot drop
packets. Because of that, `action::Mode::Ids` is the only mode actually
enforced today — verdicts are logged but never block anything.
`action::Mode::Ips` exists as the extension point: once an inline capture
backend (e.g. an NFQUEUE-based capture/verdict loop) replaces `pcap`,
`action::decide` already returns `Action::Block` for confident non-benign
verdicts and just needs to be wired to that backend.

## Training a model

`dataset.csv` accumulates labeled-as-`unknown` samples from live capture.
To get a meaningful classifier:

1. Label samples (manually, or by replaying known-bad traffic captures).
2. Train an `IdsClassifier` (see `src/ml/mod.rs`) — either directly in
   `burn`, or in another framework and import the weights (e.g. via ONNX).
3. Load the trained weights in `MlEngine` using burn's recorder API instead
   of `new_untrained`, e.g.:
   ```rust
   let record = BinFileRecorder::<FullPrecisionSettings>::new()
       .load(path.into(), &device)?;
   let model = model.load_record(record);
   ```

## Building

Requires the `libpcap` development headers/library to link against:

```sh
sudo apt-get install -y libpcap-dev
```

Then `make build` (or `cargo build`).

## Running

```sh
# Live capture from the default device (make run does this, as root/CAP_NET_RAW):
sudo ./target/debug/traffic_analyzer

# Offline: replay every packet from a previously captured file:
./target/debug/traffic_analyzer path/to/capture.pcap
```

Both modes feed the same parsing/detection/ML pipeline. Live capture runs
until interrupted; replaying a file runs until it's exhausted, then exits.
The chosen network device (live mode) or file path (offline mode) is
printed on startup; alerts are logged to stdout as `[rule] ...` or
`[ml:untrained] ...`, and every observed packet is appended to `dataset.csv`
in the working directory.
