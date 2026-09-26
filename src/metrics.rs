use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct MetricsCollector {
    inner: Arc<RwLock<MetricsState>>,
}

#[derive(Default)]
struct MetricsState {
    total_requests: u64,
    cache_hits: u64,
    cache_misses: u64,
    verification_failures: u64,
    policy_denials: u64,
    upstream_latency_ms: f64,
    active_connections: u64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MetricsState::default())),
        }
    }

    pub async fn increment_total_requests(&self) {
        let mut state = self.inner.write().await;
        state.total_requests += 1;
    }

    pub async fn increment_cache_hits(&self) {
        let mut state = self.inner.write().await;
        state.cache_hits += 1;
    }

    pub async fn increment_cache_misses(&self) {
        let mut state = self.inner.write().await;
        state.cache_misses += 1;
    }

    pub async fn increment_verification_failures(&self) {
        let mut state = self.inner.write().await;
        state.verification_failures += 1;
    }

    pub async fn increment_policy_denials(&self) {
        let mut state = self.inner.write().await;
        state.policy_denials += 1;
    }

    pub async fn record_upstream_latency(&self, ms: f64) {
        let mut state = self.inner.write().await;
        state.upstream_latency_ms = ms;
    }

    pub async fn increment_active_connections(&self) {
        let mut state = self.inner.write().await;
        state.active_connections += 1;
    }

    pub async fn decrement_active_connections(&self) {
        let mut state = self.inner.write().await;
        if state.active_connections > 0 {
            state.active_connections -= 1;
        }
    }

    pub async fn prometheus_output(&self) -> String {
        let state = self.inner.read().await;
        let mut output = String::new();

        output.push_str("# HELP aptg_total_requests Total number of requests\n");
        output.push_str("# TYPE aptg_total_requests counter\n");
        output.push_str(&format!("aptg_total_requests {}\n", state.total_requests));

        output.push_str("# HELP aptg_cache_hits Total number of cache hits\n");
        output.push_str("# TYPE aptg_cache_hits counter\n");
        output.push_str(&format!("aptg_cache_hits {}\n", state.cache_hits));

        output.push_str("# HELP aptg_cache_misses Total number of cache misses\n");
        output.push_str("# TYPE aptg_cache_misses counter\n");
        output.push_str(&format!("aptg_cache_misses {}\n", state.cache_misses));

        output
            .push_str("# HELP aptg_verification_failures Total number of verification failures\n");
        output.push_str("# TYPE aptg_verification_failures counter\n");
        output.push_str(&format!(
            "aptg_verification_failures {}\n",
            state.verification_failures
        ));

        output.push_str("# HELP aptg_policy_denials Total number of policy denials\n");
        output.push_str("# TYPE aptg_policy_denials counter\n");
        output.push_str(&format!("aptg_policy_denials {}\n", state.policy_denials));

        output.push_str("# HELP aptg_upstream_latency_ms Upstream latency in milliseconds\n");
        output.push_str("# TYPE aptg_upstream_latency_ms gauge\n");
        output.push_str(&format!(
            "aptg_upstream_latency_ms {}\n",
            state.upstream_latency_ms
        ));

        output.push_str("# HELP aptg_active_connections Number of active connections\n");
        output.push_str("# TYPE aptg_active_connections gauge\n");
        output.push_str(&format!(
            "aptg_active_connections {}\n",
            state.active_connections
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector() {
        let metrics = MetricsCollector::new();
        metrics.increment_total_requests().await;
        metrics.increment_cache_hits().await;
        metrics.increment_cache_misses().await;
        metrics.increment_verification_failures().await;
        metrics.increment_policy_denials().await;
        metrics.record_upstream_latency(42.5).await;
        metrics.increment_active_connections().await;

        let output = metrics.prometheus_output().await;
        assert!(output.contains("aptg_total_requests 1"));
        assert!(output.contains("aptg_cache_hits 1"));
        assert!(output.contains("aptg_cache_misses 1"));
        assert!(output.contains("aptg_verification_failures 1"));
        assert!(output.contains("aptg_policy_denials 1"));
        assert!(output.contains("aptg_upstream_latency_ms 42.5"));
        assert!(output.contains("aptg_active_connections 1"));
    }
}
