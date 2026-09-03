pub mod correlator;
pub mod drift;
pub mod notifier;
pub mod operator;
pub mod process_tree;
pub mod prompt_parser;
pub mod reconstructor;
pub mod rules;
pub mod summarizer;
pub mod trigger;
pub mod watcher;

pub use correlator::{CorrelatedSessionReport, SessionCorrelator, TimelineEntry};
pub use drift::{DriftReport, PromptDriftDetector};
pub use notifier::{NotificationReport, TelegramConfig, TelegramNotifier};
pub use operator::OperatorRegistry;
pub use process_tree::{ProcessNode, ProcessTreeBuilder};
pub use prompt_parser::ClaudePromptParser;
pub use reconstructor::{
    ActivityKind, KeystrokeReconstructor, ReconstructedActivity, ReconstructedSession,
};
pub use rules::{AnomalyAlert, RuleEngine};
pub use summarizer::SemanticSummarizer;
pub use trigger::{
    AiAwareTriggerEvaluator, SessionType, TriggerConfig, TriggerEvaluation, TriggerReason,
};
pub use watcher::SessionWatcher;
