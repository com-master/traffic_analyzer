use crate::features::FeatureVector;
use std::net::Ipv4Addr;
use std::time::SystemTime;

/// Writes labeled/unlabeled feature rows to a CSV file so they can be used
/// later to train the ML model offline (e.g. with Python or directly with
/// `burn`). Live capture has no ground truth, so `label` is normally
/// "unknown"; labeled datasets are produced by replaying pcaps of known
/// traffic and passing the matching label in.
pub struct DatasetWriter {
    writer: csv::Writer<std::fs::File>,
}

impl DatasetWriter {
    pub fn create(path: &str) -> csv::Result<Self> {
        let writer = csv::Writer::from_path(path)?;
        let mut dataset = DatasetWriter { writer };
        dataset.write_header()?;
        Ok(dataset)
    }

    fn write_header(&mut self) -> csv::Result<()> {
        let mut header = vec!["timestamp_unix", "src_ip", "dst_ip"];
        header.extend(FeatureVector::FIELD_NAMES);
        header.push("label");
        self.writer.write_record(&header)
    }

    pub fn write_sample(
        &mut self,
        captured_at: SystemTime,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        features: &FeatureVector,
        label: &str,
    ) -> csv::Result<()> {
        let timestamp = captured_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let mut record = vec![timestamp.to_string(), src_ip.to_string(), dst_ip.to_string()];
        record.extend(features.to_array().iter().map(|v| v.to_string()));
        record.push(label.to_string());
        self.writer.write_record(&record)
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
