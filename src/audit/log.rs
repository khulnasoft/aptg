use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};
use warp::http::{HeaderMap, Method};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub client_ip: Option<IpAddr>,
    pub method: Option<String>,
    pub path: String,
    pub user_agent: Option<String>,
    pub status: AuditStatus,
    pub message: Option<String>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Request,
    CacheHit,
    FetchSuccess,
    FetchError,
    PolicyViolation,
    VerificationFailed,
    VerificationSuccess,
    GeoIPDenied,
    GeoIPAllowed,
    GeoIPRateLimit,
    GeoIPRedirect,
    GeoIPLogOnly,
    GeoIPError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditStatus {
    Success,
    Warning,
    Error,
    Info,
    Failed,
}

const DEFAULT_MAX_FILE_SIZE_MB: u64 = 10;
const DEFAULT_MAX_BACKUP_FILES: usize = 5;

pub struct AuditLogger {
    path: Option<String>,
    max_file_size_bytes: u64,
    max_backup_files: usize,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            path: None,
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_MB * 1024 * 1024,
            max_backup_files: DEFAULT_MAX_BACKUP_FILES,
        }
    }

    pub fn with_log_file(path: impl Into<String>) -> Self {
        Self {
            path: Some(path.into()),
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_MB * 1024 * 1024,
            max_backup_files: DEFAULT_MAX_BACKUP_FILES,
        }
    }

    pub fn with_max_file_size_mb(mut self, mb: u64) -> Self {
        self.max_file_size_bytes = mb * 1024 * 1024;
        self
    }

    pub fn with_max_backup_files(mut self, n: usize) -> Self {
        self.max_backup_files = n;
        self
    }

    pub async fn log_request(&self, method: &Method, path: &str, headers: &HeaderMap) {
        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::Request,
            client_ip: None,
            method: Some(method.to_string()),
            path: path.to_string(),
            user_agent,
            status: AuditStatus::Info,
            message: Some("Request received".to_string()),
            duration_ms: None,
        };

        info!("Request: {} {} from {:?}", method, path, event.user_agent);
        let _ = self.write_event(&event).await;
    }

    pub async fn log_cache_hit(&self, path: &str) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::CacheHit,
            client_ip: None,
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Info,
            message: Some("Cache hit".to_string()),
            duration_ms: None,
        };

        info!("Cache hit: {}", path);
        let _ = self.write_event(&event).await;
    }

    pub async fn log_fetch_success(&self, path: &str) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::FetchSuccess,
            client_ip: None,
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Success,
            message: Some("Successfully fetched from upstream".to_string()),
            duration_ms: None,
        };

        info!("Fetch success: {}", path);
        let _ = self.write_event(&event).await;
    }

    pub async fn log_fetch_error(&self, path: &str, error: &anyhow::Error) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::FetchError,
            client_ip: None,
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Error,
            message: Some(format!("Fetch error: {}", error)),
            duration_ms: None,
        };

        error!("Fetch error for {}: {}", path, error);
        let _ = self.write_event(&event).await;
    }

    pub async fn log_policy_violation(&self, path: &str, reason: &str) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::PolicyViolation,
            client_ip: None,
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Warning,
            message: Some(format!("Policy violation: {}", reason)),
            duration_ms: None,
        };

        warn!("Policy violation for {}: {}", path, reason);
        let _ = self.write_event(&event).await;
    }

    pub async fn log_verification_success(&self, path: &str) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::VerificationSuccess,
            client_ip: None,
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Success,
            message: Some("GPG verification successful".to_string()),
            duration_ms: None,
        };

        let _ = self.write_event(&event).await;
    }

    pub async fn log_verification_failed(&self, path: &str, reason: &str) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::VerificationFailed,
            client_ip: None,
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Failed,
            message: Some(format!("GPG verification failed: {}", reason)),
            duration_ms: None,
        };

        let _ = self.write_event(&event).await;
    }

    pub async fn log_geoip_denied(&self, client_ip: &str, path: &str, reason: &str) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::GeoIPDenied,
            client_ip: client_ip.parse().ok(),
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Warning,
            message: Some(format!("GeoIP denied: {}", reason)),
            duration_ms: None,
        };

        warn!(
            "GeoIP denied request from {} to {}: {}",
            client_ip, path, reason
        );
        let _ = self.write_event(&event).await;
    }

    pub async fn log_geoip_allowed(&self, client_ip: &str, path: &str, reason: &str) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::GeoIPAllowed,
            client_ip: client_ip.parse().ok(),
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Success,
            message: Some(format!("GeoIP allowed: {}", reason)),
            duration_ms: None,
        };

        info!(
            "GeoIP allowed request from {} to {}: {}",
            client_ip, path, reason
        );
        let _ = self.write_event(&event).await;
    }

    pub async fn log_geoip_rate_limit(&self, client_ip: &str, path: &str, limit: u32) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::GeoIPRateLimit,
            client_ip: client_ip.parse().ok(),
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Warning,
            message: Some(format!("GeoIP rate limited: {} requests/minute", limit)),
            duration_ms: None,
        };

        warn!(
            "GeoIP rate limited request from {} to {}: {} requests/minute",
            client_ip, path, limit
        );
        let _ = self.write_event(&event).await;
    }

    pub async fn log_geoip_redirect(&self, client_ip: &str, path: &str, redirect_url: &str) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::GeoIPRedirect,
            client_ip: client_ip.parse().ok(),
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Info,
            message: Some(format!("GeoIP redirect to: {}", redirect_url)),
            duration_ms: None,
        };

        info!(
            "GeoIP redirected request from {} to {} to: {}",
            client_ip, path, redirect_url
        );
        let _ = self.write_event(&event).await;
    }

    pub async fn log_geoip_log_only(&self, client_ip: &str, path: &str, reason: &str) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::GeoIPLogOnly,
            client_ip: client_ip.parse().ok(),
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Info,
            message: Some(format!("GeoIP log only: {}", reason)),
            duration_ms: None,
        };

        info!(
            "GeoIP logged request from {} to {}: {}",
            client_ip, path, reason
        );
        let _ = self.write_event(&event).await;
    }

    pub async fn log_geoip_error(&self, client_ip: &str, path: &str, error: &anyhow::Error) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::GeoIPError,
            client_ip: client_ip.parse().ok(),
            method: None,
            path: path.to_string(),
            user_agent: None,
            status: AuditStatus::Error,
            message: Some(format!("GeoIP error: {}", error)),
            duration_ms: None,
        };

        error!("GeoIP error for {} to {}: {}", client_ip, path, error);
        let _ = self.write_event(&event).await;
    }

    async fn write_event(&self, event: &AuditEvent) -> anyhow::Result<()> {
        let json = serde_json::to_string(event)?;
        info!("Audit: {}", json);

        let Some(path) = &self.path else {
            return Ok(());
        };

        if let Some(parent) = std::path::Path::new(path).parent() {
            fs::create_dir_all(parent).await.ok();
        }

        self.rotate_if_needed(path).await?;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }

    async fn rotate_if_needed(&self, path: &str) -> anyhow::Result<()> {
        let metadata = match fs::metadata(path).await {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        if metadata.len() < self.max_file_size_bytes {
            return Ok(());
        }

        for i in (1..=self.max_backup_files as u64).rev() {
            let src = if i == 1 {
                format!("{}.0", path)
            } else {
                format!("{}.{}", path, i - 1)
            };
            let dst = format!("{}.{}", path, i);
            let _ = fs::rename(&src, &dst).await;
        }

        fs::rename(path, format!("{}.0", path)).await?;
        Ok(())
    }

    pub async fn get_recent_events(&self, limit: usize) -> Vec<AuditEvent> {
        let Some(path) = &self.path else {
            return vec![];
        };
        let content = match fs::read_to_string(path).await {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let mut events: Vec<AuditEvent> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        events.reverse();
        events.truncate(limit);
        events.reverse();
        events
    }

    pub async fn export_events(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<AuditEvent> {
        let Some(path) = &self.path else {
            return vec![];
        };
        let content = match fs::read_to_string(path).await {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        content
            .lines()
            .filter_map(|line| serde_json::from_str::<AuditEvent>(line).ok())
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::HeaderMap;

    #[tokio::test]
    async fn audit_logger_writes_and_reads_events() {
        let dir = tempfile::tempdir().expect("temp dir");
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::with_log_file(log_path.to_str().unwrap());

        logger
            .log_request(&Method::GET, "/debian/test", &HeaderMap::new())
            .await;
        logger.log_cache_hit("/debian/cached").await;

        let events = logger.get_recent_events(10).await;
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].event_type, AuditEventType::Request));
        assert!(matches!(events[1].event_type, AuditEventType::CacheHit));
    }

    #[tokio::test]
    async fn export_events_filters_by_time() {
        let dir = tempfile::tempdir().expect("temp dir");
        let log_path = dir.path().join("audit2.jsonl");
        let logger = AuditLogger::with_log_file(log_path.to_str().unwrap());

        logger
            .log_request(&Method::GET, "/before", &HeaderMap::new())
            .await;
        let mid = Utc::now();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        logger.log_cache_hit("/after").await;

        let exported = logger
            .export_events(Utc::now() - chrono::Duration::hours(1), mid)
            .await;
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].path, "/before");
    }

    #[tokio::test]
    async fn log_rotation_renames_existing_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let log_path = dir.path().join("audit3.jsonl");
        let logger = AuditLogger::with_log_file(log_path.to_str().unwrap())
            .with_max_file_size_mb(0)
            .with_max_backup_files(3);

        logger
            .log_request(&Method::GET, "/rotated", &HeaderMap::new())
            .await;
        logger.log_cache_hit("/rotated2").await;

        assert!(log_path.exists());
        let backup = format!("{}.0", log_path.display());
        assert!(std::path::Path::new(&backup).exists());
    }
}
