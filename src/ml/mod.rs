use crate::features::FeatureVector;
use burn::backend::NdArray;
use burn::config::Config;
use burn::module::Module;
use burn::nn::{Linear, LinearConfig, Relu};
use burn::tensor::activation::softmax;
use burn::tensor::backend::{Backend, BackendTypes};
use burn::tensor::Tensor;

/// CPU inference backend. Burn also supports wgpu/cuda/tch/candle backends
/// behind feature flags if GPU inference is needed later; ndarray is
/// enough for a per-packet tabular classifier on commodity hardware.
pub type InferenceBackend = NdArray<f32>;

/// Small feed-forward classifier over [`FeatureVector`]s. Architecture is a
/// placeholder (3 linear layers + ReLU) - what matters at this stage is
/// that parsing -> features -> tensor -> verdict is wired end-to-end, not
/// the specific topology, which should be revisited once real training
/// data is available.
#[derive(Module, Debug)]
pub struct IdsClassifier<B: Backend> {
    fc1: Linear<B>,
    fc2: Linear<B>,
    fc3: Linear<B>,
    relu: Relu,
}

#[derive(Config, Debug)]
pub struct IdsClassifierConfig {
    pub input_size: usize,
    pub hidden_size: usize,
    pub num_classes: usize,
}

impl IdsClassifierConfig {
    pub fn init<B: Backend>(&self, device: &B::Device) -> IdsClassifier<B> {
        IdsClassifier {
            fc1: LinearConfig::new(self.input_size, self.hidden_size).init(device),
            fc2: LinearConfig::new(self.hidden_size, self.hidden_size).init(device),
            fc3: LinearConfig::new(self.hidden_size, self.num_classes).init(device),
            relu: Relu::new(),
        }
    }
}

impl<B: Backend> IdsClassifier<B> {
    pub fn forward(&self, input: Tensor<B, 2>) -> Tensor<B, 2> {
        let x = self.relu.forward(self.fc1.forward(input));
        let x = self.relu.forward(self.fc2.forward(x));
        self.fc3.forward(x)
    }
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub label: String,
    pub confidence: f32,
}

/// Owns the model plus the class labels it outputs.
///
/// IMPORTANT: `new_untrained` initializes the network with random weights.
/// It lets the full pipeline (capture -> features -> ML verdict -> action)
/// run end-to-end today, but the verdicts are not meaningful until a real
/// model is trained and its weights are loaded here - see `load_weights`.
pub struct MlEngine {
    model: IdsClassifier<InferenceBackend>,
    device: <InferenceBackend as BackendTypes>::Device,
    labels: Vec<String>,
}

impl MlEngine {
    pub fn new_untrained(labels: Vec<String>) -> Self {
        let device = <InferenceBackend as BackendTypes>::Device::default();
        let config = IdsClassifierConfig::new(FeatureVector::LEN, 32, labels.len());
        let model = config.init(&device);
        Self {
            model,
            device,
            labels,
        }
    }

    // TODO: once a model has been trained (in burn directly, or trained
    // elsewhere and converted - e.g. via ONNX import), load its weights
    // here with burn's recorder API instead of `new_untrained`, e.g.:
    //   let record = BinFileRecorder::<FullPrecisionSettings>::new()
    //       .load(path.into(), &device)?;
    //   let model = model.load_record(record);

    pub fn predict(&self, features: &FeatureVector) -> Verdict {
        let input: Tensor<InferenceBackend, 1> =
            Tensor::from_floats(features.to_array(), &self.device);
        let logits = self.model.forward(input.unsqueeze::<2>());
        let probabilities = softmax(logits, 1);

        let scores = probabilities
            .into_data()
            .into_vec::<f32>()
            .expect("ndarray backend yields f32 tensor data");

        let (class_idx, &confidence) = scores
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .expect("labels must be non-empty");

        Verdict {
            label: self.labels[class_idx].clone(),
            confidence,
        }
    }
}
