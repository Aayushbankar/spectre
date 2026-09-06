use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Default)]
pub struct PipelineStats {
    pub events_ingested: AtomicU64,
    pub alerts_triggered: AtomicU64,
    pub mitigations_executed: AtomicU64,
    pub dropped_events: AtomicU64,
}

impl PipelineStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_ingested(&self) {
        self.events_ingested.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_alerts(&self) {
        self.alerts_triggered.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_mitigations(&self) {
        self.mitigations_executed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_drops(&self) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn spawn_metrics_reporter(stats: Arc<PipelineStats>, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut last_ingested = 0;
        loop {
            ticker.tick().await;

            let total_ingested = stats.events_ingested.load(Ordering::Relaxed);
            let total_alerts = stats.alerts_triggered.load(Ordering::Relaxed);
            let total_mitigations = stats.mitigations_executed.load(Ordering::Relaxed);
            let total_drops = stats.dropped_events.load(Ordering::Relaxed);

            let delta = total_ingested.saturating_sub(last_ingested);
            last_ingested = total_ingested;
            let eps = delta as f64 / interval.as_secs_f64();

            log::info!(
                "📊 [TELEMETRY] Throughput: {:.1} eps | Ingested: {} | Alerts: {} | Mitigations: {} | Drops: {}",
                eps, total_ingested, total_alerts, total_mitigations, total_drops
            );
        }
    })
}
