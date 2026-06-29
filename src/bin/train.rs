//! Trains `IdsClassifier` on a labeled `dataset.csv` (see `label_dataset`)
//! and saves the resulting weights so `MlEngine` can load them instead of
//! `new_untrained`'s random weights.
//!
//! Usage:
//!   train <labeled.csv> <weights_out.bin> [--epochs N] [--lr F] [--hidden N] [--batch-size N] [--val-split F]

use burn::backend::{Autodiff, NdArray};
use burn::module::{AutodiffModule, Module};
use burn::nn::loss::CrossEntropyLossConfig;
use burn::optim::{AdamConfig, GradientsParams, Optimizer};
use burn::record::{BinFileRecorder, FullPrecisionSettings};
use burn::tensor::backend::BackendTypes;
use burn::tensor::{ElementConversion, Int, Shape, Tensor, TensorData};
use rand::seq::SliceRandom;
use std::env;
use std::process::ExitCode;
use traffic_analyzer::features::FeatureVector;
use traffic_analyzer::ml::{IdsClassifier, IdsClassifierConfig, HIDDEN_SIZE};

/// Must match the class labels `main.rs` constructs `MlEngine` with.
const LABELS: [&str; 5] = [
    "benign",
    "tcp_anomaly",
    "tcp_syn_anomaly",
    "udp_anomaly",
    "icmp_anomaly",
];

type TrainBackend = Autodiff<NdArray<f32>>;

struct Args {
    input_csv: String,
    weights_out: String,
    epochs: usize,
    lr: f64,
    hidden_size: usize,
    batch_size: usize,
    val_split: f32,
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let raw: Vec<String> = env::args().collect();
    let mut positional = Vec::new();
    let mut epochs = 50;
    let mut lr = 1e-3;
    let mut hidden_size = HIDDEN_SIZE;
    let mut batch_size = 32;
    let mut val_split = 0.2;

    let mut i = 1;
    while i < raw.len() {
        match raw[i].as_str() {
            "--epochs" => {
                i += 1;
                epochs = raw.get(i).ok_or("--epochs requires a value")?.parse()?;
            }
            "--lr" => {
                i += 1;
                lr = raw.get(i).ok_or("--lr requires a value")?.parse()?;
            }
            "--hidden" => {
                i += 1;
                hidden_size = raw.get(i).ok_or("--hidden requires a value")?.parse()?;
            }
            "--batch-size" => {
                i += 1;
                batch_size = raw.get(i).ok_or("--batch-size requires a value")?.parse()?;
            }
            "--val-split" => {
                i += 1;
                val_split = raw.get(i).ok_or("--val-split requires a value")?.parse()?;
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    if positional.len() != 2 {
        return Err("usage: train <labeled.csv> <weights_out.bin> [--epochs N] [--lr F] [--hidden N] [--batch-size N] [--val-split F]".into());
    }

    Ok(Args {
        input_csv: positional[0].clone(),
        weights_out: positional[1].clone(),
        epochs,
        lr,
        hidden_size,
        batch_size,
        val_split,
    })
}

/// Loads `(features, label_index)` pairs from a labeled dataset CSV. Rows
/// whose label isn't one of `LABELS` (e.g. still "unknown") are skipped -
/// they carry no usable ground truth.
fn load_samples(path: &str) -> Result<Vec<([f32; FeatureVector::LEN], usize)>, Box<dyn std::error::Error>> {
    let mut reader = csv::Reader::from_path(path)?;
    let header = reader.headers()?.clone();

    let feature_indices: Vec<usize> = FeatureVector::FIELD_NAMES
        .iter()
        .map(|name| {
            header
                .iter()
                .position(|h| h == *name)
                .ok_or_else(|| format!("input csv missing column {}", name))
        })
        .collect::<Result<_, _>>()?;
    let label_idx = header
        .iter()
        .position(|h| h == "label")
        .ok_or("input csv missing label column")?;

    let mut samples = Vec::new();
    let mut skipped = 0u64;
    for result in reader.records() {
        let record = result?;
        let label = &record[label_idx];
        let Some(class) = LABELS.iter().position(|l| *l == label) else {
            skipped += 1;
            continue;
        };
        let mut features = [0f32; FeatureVector::LEN];
        for (slot, &col) in feature_indices.iter().enumerate() {
            features[slot] = record[col].parse()?;
        }
        samples.push((features, class));
    }

    if skipped > 0 {
        println!("Skipped {} row(s) with a label outside {:?}", skipped, LABELS);
    }
    Ok(samples)
}

fn batch_tensors(
    batch: &[([f32; FeatureVector::LEN], usize)],
    device: &<TrainBackend as BackendTypes>::Device,
) -> (Tensor<TrainBackend, 2>, Tensor<TrainBackend, 1, Int>) {
    let mut flat_features = Vec::with_capacity(batch.len() * FeatureVector::LEN);
    let mut targets = Vec::with_capacity(batch.len());
    for (features, class) in batch {
        flat_features.extend_from_slice(features);
        targets.push(*class as i64);
    }

    let input = Tensor::from_data(
        TensorData::new(flat_features, Shape::new([batch.len(), FeatureVector::LEN])),
        device,
    );
    let target = Tensor::from_data(TensorData::new(targets, Shape::new([batch.len()])), device);
    (input, target)
}

fn accuracy(logits: &Tensor<TrainBackend, 2>, targets: &Tensor<TrainBackend, 1, Int>) -> f32 {
    let predicted = logits.clone().argmax(1).squeeze::<1>();
    let correct: i64 = predicted
        .equal(targets.clone())
        .int()
        .sum()
        .into_scalar()
        .elem();
    correct as f32 / targets.dims()[0] as f32
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let mut samples = load_samples(&args.input_csv)?;
    if samples.is_empty() {
        return Err("no labeled samples found - run label_dataset first".into());
    }

    let mut rng = rand::thread_rng();
    samples.shuffle(&mut rng);

    let val_count = ((samples.len() as f32) * args.val_split).round() as usize;
    let (val_samples, train_samples) = {
        let split = samples.split_off(samples.len() - val_count.min(samples.len() - 1).max(1));
        (split, samples)
    };
    println!(
        "{} training samples, {} validation samples",
        train_samples.len(),
        val_samples.len()
    );

    let device = <TrainBackend as BackendTypes>::Device::default();
    let mut model: IdsClassifier<TrainBackend> =
        IdsClassifierConfig::new(FeatureVector::LEN, args.hidden_size, LABELS.len()).init(&device);
    let loss_fn = CrossEntropyLossConfig::new().init(&device);
    let mut optim = AdamConfig::new().init();

    for epoch in 1..=args.epochs {
        let mut epoch_loss = 0f32;
        let mut batch_count = 0usize;
        for batch in train_samples.chunks(args.batch_size) {
            let (input, target) = batch_tensors(batch, &device);
            let logits = model.forward(input);
            let loss = loss_fn.forward(logits, target);
            epoch_loss += loss.clone().into_scalar().elem::<f32>();
            batch_count += 1;

            let grads = loss.backward();
            let grads = GradientsParams::from_grads(grads, &model);
            model = optim.step(args.lr, model, grads);
        }

        if epoch % 5 == 0 || epoch == args.epochs {
            let (val_input, val_target) = batch_tensors(&val_samples, &device);
            let val_logits = model.forward(val_input);
            let val_acc = accuracy(&val_logits, &val_target);
            println!(
                "epoch {:>3}: train_loss={:.4} val_acc={:.3}",
                epoch,
                epoch_loss / batch_count.max(1) as f32,
                val_acc
            );
        }
    }

    let trained = model.valid();
    trained.save_file(
        &args.weights_out,
        &BinFileRecorder::<FullPrecisionSettings>::new(),
    )?;
    println!("Saved trained weights to {}", args.weights_out);

    Ok(())
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
