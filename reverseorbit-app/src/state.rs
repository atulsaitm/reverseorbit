use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::{Mutex, broadcast};

use reverseorbit_core::{CaseStore, ServerEvent};
use reverseorbit_radare2::Radare2Adapter;

use crate::adapter::AnalysisAdapter;

const DEFAULT_ACTION_TIMEOUT_SECONDS: u64 = 90;

#[derive(Debug, Clone)]
pub struct AppState {
    pub store: CaseStore,
    pub adapter: Arc<dyn AnalysisAdapter>,
    pub broadcaster: broadcast::Sender<ServerEvent>,
    pub action_guard: Arc<Mutex<()>>,
    pub action_timeout: Duration,
    pub web_dist_dir: PathBuf,
}

pub fn build_state(cases_dir: PathBuf, web_dist_dir: PathBuf) -> AppState {
    build_state_with_adapter(
        cases_dir,
        web_dist_dir,
        Arc::new(Radare2Adapter::new()),
    )
}

pub fn build_state_with_adapter(
    cases_dir: PathBuf,
    web_dist_dir: PathBuf,
    adapter: Arc<dyn AnalysisAdapter>,
) -> AppState {
    build_state_with_adapter_and_action_timeout(
        cases_dir,
        web_dist_dir,
        adapter,
        Duration::from_secs(DEFAULT_ACTION_TIMEOUT_SECONDS),
    )
}

pub fn build_state_with_adapter_and_action_timeout(
    cases_dir: PathBuf,
    web_dist_dir: PathBuf,
    adapter: Arc<dyn AnalysisAdapter>,
    action_timeout: Duration,
) -> AppState {
    let (broadcaster, _) = broadcast::channel(256);
    AppState {
        store: CaseStore::new(cases_dir),
        adapter,
        broadcaster,
        action_guard: Arc::new(Mutex::new(())),
        action_timeout,
        web_dist_dir,
    }
}

