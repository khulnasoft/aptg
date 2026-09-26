use crate::policy::rules::{PolicyConfig, PolicyEngine};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub https_port: u16,
    pub enable_https: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
    pub client_auth_required: bool,
    pub min_tls_version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub base_url: String,
    pub suite: String,
    pub timeout_seconds: u64,
    pub verify_ssl: bool,
    pub ca_cert_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    pub release_ttl: i64,
    pub packages_ttl: i64,
    pub deb_ttl: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    pub log_level: String,
    pub log_file: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationConfig {
    pub gpg_keyring_path: String,
    pub enable_gpg_verification: bool,
    pub enable_hash_verification: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub upstream: UpstreamConfig,
    pub cache: CacheConfig,
    pub audit: AuditConfig,
    pub verification: VerificationConfig,
    pub policy: PolicyConfig,
}

static CONFIG_MTIME: AtomicU64 = AtomicU64::new(0);

impl AppConfig {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read config {}: {}", path.display(), e))?;
        let config: AppConfig = toml::from_str(&content)
            .map_err(|e| anyhow!("failed to parse config {}: {}", path.display(), e))?;
        config.apply_audit_to_tracing();
        Ok(config)
    }

    fn apply_audit_to_tracing(&self) {
        let level = self.audit.log_level.as_str();
        tracing::dispatcher::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(match level {
                    "error" => tracing::Level::ERROR,
                    "warn" => tracing::Level::WARN,
                    "info" => tracing::Level::INFO,
                    "debug" => tracing::Level::DEBUG,
                    "trace" => tracing::Level::TRACE,
                    _ => tracing::Level::INFO,
                })
                .with_target(false)
                .with_thread_ids(true)
                .with_file(true)
                .finish()
                .into(),
        )
        .ok();
    }

    pub fn spawn_watcher(
        self_: Arc<RwLock<Self>>,
        path: PathBuf,
        policy_engine: Arc<RwLock<PolicyEngine>>,
    ) {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                if let Err(e) = try_reload(&self_, &path, &policy_engine).await {
                    warn!("config watch error: {}", e);
                }
            }
        });
    }
}

async fn try_reload(
    config: &Arc<RwLock<AppConfig>>,
    path: &std::path::Path,
    policy_engine: &Arc<RwLock<PolicyEngine>>,
) -> Result<()> {
    let metadata = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(e) => return Err(anyhow!("config metadata: {}", e)),
    };
    let mtime = metadata
        .modified()
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        })
        .unwrap_or(0);
    let previous = CONFIG_MTIME.load(Ordering::Relaxed);
    if mtime > 0 && mtime == previous {
        return Ok(());
    }

    let new = AppConfig::load(path)?;
    let policy_config = new.policy.clone();
    config.write().await.clone_from(&new);
    CONFIG_MTIME.store(mtime, Ordering::Relaxed);
    policy_engine
        .write()
        .await
        .reload_from_config(policy_config);
    info!("config reloaded from {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_loads_from_toml() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[server]
host = "0.0.0.0"
port = 9090
https_port = 9443
enable_https = false

[tls]
cert_path = "c.pem"
key_path = "k.pem"
ca_path = "ca.pem"
client_auth_required = true
min_tls_version = "1.3"

[upstream]
base_url = "https://example.com"
suite = "bookworm"
timeout_seconds = 60
verify_ssl = false
ca_cert_path = "upstream-ca.pem"

[cache]
release_ttl = 100
packages_ttl = 200
deb_ttl = 300

[audit]
log_level = "debug"
log_file = "/tmp/audit.log"

[verification]
gpg_keyring_path = "/tmp/keyring.gpg"
enable_gpg_verification = false
enable_hash_verification = false

[policy.allow]
suites = ["bookworm"]
components = ["main"]
architectures = ["amd64"]

[policy.deny]
architectures = []
packages = []

[policy.limits]
max_deb_size_mb = 500
max_requests_per_minute_per_ip = 100
burst_size = 20
ban_duration_seconds = 300
"#,
        )
        .unwrap();

        let config = AppConfig::load(&path).expect("load config");
        assert_eq!(config.server.port, 9090);
        assert!(!config.server.enable_https);
        assert_eq!(config.tls.min_tls_version, "1.3");
        assert_eq!(config.upstream.timeout_seconds, 60);
        assert_eq!(config.cache.release_ttl, 100);
        assert_eq!(config.audit.log_file, "/tmp/audit.log");
        assert!(!config.verification.enable_gpg_verification);
    }
}
