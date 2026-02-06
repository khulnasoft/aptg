use std::net::IpAddr;
use warp::http::{Method, HeaderMap};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::{info, warn, error};

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

pub struct AuditLogger {
    // In a real implementation, this would write to a file or database
    // For now, we'll just log via tracing
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {}
    }
    
    pub async fn log_request(&self, method: &Method, path: &str, headers: &HeaderMap) {
        let user_agent = headers.get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
            
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::Request,
            client_ip: None, // Would extract from real connection
            method: Some(method.to_string()),
            path: path.to_string(),
            user_agent,
            status: AuditStatus::Info,
            message: Some("Request received".to_string()),
            duration_ms: None,
        };
        
        info!("Request: {} {} from {:?}", method, path, event.user_agent);
        self.write_event(&event).await;
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
        self.write_event(&event).await;
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
        self.write_event(&event).await;
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
        self.write_event(&event).await;
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
        self.write_event(&event).await;
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
        
        self.write_event(&event).await;
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
        
        self.write_event(&event).await;
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
        
        warn!("GeoIP denied request from {} to {}: {}", client_ip, path, reason);
        self.write_event(&event).await;
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
        
        info!("GeoIP allowed request from {} to {}: {}", client_ip, path, reason);
        self.write_event(&event).await;
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
        
        warn!("GeoIP rate limited request from {} to {}: {} requests/minute", client_ip, path, limit);
        self.write_event(&event).await;
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
        
        info!("GeoIP redirected request from {} to {} to: {}", client_ip, path, redirect_url);
        self.write_event(&event).await;
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
        
        info!("GeoIP logged request from {} to {}: {}", client_ip, path, reason);
        self.write_event(&event).await;
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
        self.write_event(&event).await;
    }
    
    async fn write_event(&self, event: &AuditEvent) {
        // In a real implementation, this would write to a file, database, or logging service
        // For now, we'll serialize to JSON and log it
        if let Ok(json) = serde_json::to_string(event) {
            info!("Audit: {}", json);
        }
    }
    
    pub async fn get_recent_events(&self, _limit: usize) -> Vec<AuditEvent> {
        // In a real implementation, this would query the audit storage
        // For now, return empty vector
        vec![]
    }
    
    pub async fn export_events(&self, _start_time: DateTime<Utc>, _end_time: DateTime<Utc>) -> Vec<AuditEvent> {
        // In a real implementation, this would export events within time range
        // For now, return empty vector
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_audit_logger_creation() {
        let logger = AuditLogger::new();
        // Test that it doesn't panic
        logger.log_request(&Method::GET, "/test", &HeaderMap::new()).await;
    }
}
