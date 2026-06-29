//! Relabels a `dataset.csv` produced by live/replay capture (rows default
//! to `label="unknown"`) using ground truth that's external to the pcap
//! itself: a list of attack time-windows, each naming the attacking
//! `src_ip` and the label to apply. Rows whose timestamp+src_ip fall
//! inside no window are labeled with `--default-label` (normally
//! "benign"), since most of any capture - including the run-up before an
//! attack starts - is ordinary traffic.
//!
//! Usage:
//!   label_dataset <input.csv> <windows.csv> <output.csv> [--default-label benign]
//!
//! windows.csv format (one window per line, '#' starts a comment):
//!   start_unix,end_unix,src_ip,label
//!   1700000010,1700000090,203.0.113.7,tcp_syn_anomaly

use std::env;
use std::process::ExitCode;

struct AttackWindow {
    start: f64,
    end: f64,
    src_ip: String,
    label: String,
}

fn load_windows(path: &str) -> Result<Vec<AttackWindow>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let mut windows = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(|f| f.trim()).collect();
        if fields.len() != 4 {
            return Err(format!(
                "windows file line {}: expected 4 comma-separated fields, got {}",
                line_no + 1,
                fields.len()
            )
            .into());
        }
        windows.push(AttackWindow {
            start: fields[0].parse()?,
            end: fields[1].parse()?,
            src_ip: fields[2].to_string(),
            label: fields[3].to_string(),
        });
    }
    Ok(windows)
}

fn label_for(windows: &[AttackWindow], timestamp: f64, src_ip: &str, default_label: &str) -> String {
    for window in windows {
        if src_ip == window.src_ip && timestamp >= window.start && timestamp <= window.end {
            return window.label.clone();
        }
    }
    default_label.to_string()
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut positional = Vec::new();
    let mut default_label = "benign".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--default-label" => {
                i += 1;
                default_label = args
                    .get(i)
                    .ok_or("--default-label requires a value")?
                    .clone();
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    if positional.len() != 3 {
        return Err(
            "usage: label_dataset <input.csv> <windows.csv> <output.csv> [--default-label benign]"
                .into(),
        );
    }
    let (input_path, windows_path, output_path) = (&positional[0], &positional[1], &positional[2]);

    let windows = load_windows(windows_path)?;
    println!("Loaded {} attack window(s) from {}", windows.len(), windows_path);

    let mut reader = csv::Reader::from_path(input_path)?;
    let header = reader.headers()?.clone();
    let timestamp_idx = header
        .iter()
        .position(|h| h == "timestamp_unix")
        .ok_or("input csv missing timestamp_unix column")?;
    let src_ip_idx = header
        .iter()
        .position(|h| h == "src_ip")
        .ok_or("input csv missing src_ip column")?;
    let label_idx = header
        .iter()
        .position(|h| h == "label")
        .ok_or("input csv missing label column")?;

    let mut writer = csv::Writer::from_path(output_path)?;
    writer.write_record(&header)?;

    let mut counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for result in reader.records() {
        let mut record = result?;
        let timestamp: f64 = record[timestamp_idx].parse()?;
        let src_ip = record[src_ip_idx].to_string();
        let label = label_for(&windows, timestamp, &src_ip, &default_label);
        *counts.entry(label.clone()).or_insert(0) += 1;
        record = {
            let mut fields: Vec<String> = record.iter().map(|f| f.to_string()).collect();
            fields[label_idx] = label;
            csv::StringRecord::from(fields)
        };
        writer.write_record(&record)?;
    }
    writer.flush()?;

    println!("Wrote {} with label counts:", output_path);
    let mut counts: Vec<_> = counts.into_iter().collect();
    counts.sort_by(|a, b| a.0.cmp(&b.0));
    for (label, count) in counts {
        println!("  {}: {}", label, count);
    }

    Ok(())
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
