use crate::mirror::path::{DebianPath, PathParser, PathType};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tracing::info;
use warp::http::Method;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    pub allow: AllowPolicy,
    pub deny: DenyPolicy,
    pub limits: LimitsPolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowPolicy {
    pub suites: Vec<String>,
    pub components: Vec<String>,
    pub architectures: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DenyPolicy {
    pub architectures: Vec<String>,
    pub packages: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsPolicy {
    pub max_deb_size_mb: u64,
    pub max_requests_per_minute_per_ip: u32,
    pub burst_size: usize,
    pub ban_duration_seconds: u64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allow: AllowPolicy {
                suites: vec!["bookworm".to_string(), "bullseye".to_string()],
                components: vec![
                    "main".to_string(),
                    "contrib".to_string(),
                    "non-free".to_string(),
                ],
                architectures: vec![
                    "amd64".to_string(),
                    "arm64".to_string(),
                    "binary-amd64".to_string(),
                ],
            },
            deny: DenyPolicy {
                architectures: vec!["i386".to_string()],
                packages: vec![],
            },
            limits: LimitsPolicy {
                max_deb_size_mb: 500,
                max_requests_per_minute_per_ip: 100,
                burst_size: 20,
                ban_duration_seconds: 300,
            },
        }
    }
}

pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_requests_per_minute: u32,
    burst_size: usize,
    handle: Handle,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32, burst_size: usize) -> Self {
        let handle = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
            .handle()
            .clone();
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests_per_minute,
            burst_size,
            handle,
        }
    }

    pub async fn check(&self, client_ip: &str) -> Result<()> {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        let client_requests = requests
            .entry(client_ip.to_string())
            .or_insert_with(Vec::new);
        client_requests.retain(|&t| t > one_minute_ago);

        if client_requests.len() >= self.burst_size {
            return Err(anyhow!(
                "Rate limit exceeded for client {}: burst size {} reached",
                client_ip,
                self.burst_size
            ));
        }

        if client_requests.len() as u32 >= self.max_requests_per_minute {
            return Err(anyhow!(
                "Rate limit exceeded for client {}: max {} requests per minute",
                client_ip,
                self.max_requests_per_minute
            ));
        }

        client_requests.push(now);
        Ok(())
    }

    pub fn check_blocking(&self, client_ip: &str) -> Result<()> {
        self.handle.block_on(self.check(client_ip))
    }
}

pub struct PolicyEngine {
    config: PolicyConfig,
    allowed_suites: HashSet<String>,
    allowed_components: HashSet<String>,
    allowed_architectures: HashSet<String>,
    denied_architectures: HashSet<String>,
    denied_packages: HashSet<String>,
    rate_limiter: RateLimiter,
    banlist: HashSet<String>,
    banned_until: HashMap<String, Instant>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        let config = PolicyConfig::default();
        Self::from_config(config)
    }

    pub fn from_config(config: PolicyConfig) -> Self {
        let allowed_suites: HashSet<String> = config.allow.suites.iter().cloned().collect();
        let allowed_components: HashSet<String> = config.allow.components.iter().cloned().collect();
        let allowed_architectures: HashSet<String> =
            config.allow.architectures.iter().cloned().collect();
        let denied_architectures: HashSet<String> =
            config.deny.architectures.iter().cloned().collect();
        let denied_packages: HashSet<String> = config.deny.packages.iter().cloned().collect();

        let rate_limiter = RateLimiter::new(
            config.limits.max_requests_per_minute_per_ip,
            config.limits.burst_size,
        );

        Self {
            config,
            allowed_suites,
            allowed_components,
            allowed_architectures,
            denied_architectures,
            denied_packages,
            rate_limiter,
            banlist: HashSet::new(),
            banned_until: HashMap::new(),
        }
    }

    pub fn check_request(&self, client_ip: &str, path: &str, method: &Method) -> Result<bool> {
        self.check_banlist(client_ip)?;
        self.rate_limiter.check_blocking(client_ip)?;

        if method != Method::GET && method != Method::HEAD {
            return Ok(false);
        }
        Ok(self.check_path(path).is_ok())
    }

    pub fn check_path(&self, path: &str) -> Result<()> {
        info!("Checking policy for path: {}", path);

        let debian_path = PathParser::parse_debian_path(path)
            .map_err(|e| anyhow!("Invalid Debian path: {}", e))?;

        match debian_path.path_type {
            PathType::Release => self.check_release_policy(&debian_path),
            PathType::Package => self.check_package_policy(&debian_path),
        }
    }

    pub fn check_rate_limit(&self, client_ip: &str) -> Result<()> {
        self.rate_limiter.check_blocking(client_ip)
    }

    pub fn check_banlist(&self, client_ip: &str) -> Result<()> {
        if self.banlist.contains(client_ip) {
            if let Some(banned_until) = self.banned_until.get(client_ip) {
                if Instant::now() < *banned_until {
                    return Err(anyhow!(
                        "Client {} is banned until {:?}",
                        client_ip,
                        banned_until
                    ));
                }
            }
            return Err(anyhow!("Client {} is banned", client_ip));
        }
        Ok(())
    }

    pub fn ban_client(&mut self, ip: &str, duration: Duration) {
        self.banlist.insert(ip.to_string());
        self.banned_until
            .insert(ip.to_string(), Instant::now() + duration);
        self.rate_limiter.requests.blocking_write().remove(ip);
        info!("Client {} banned for {:?}", ip, duration);
    }

    pub fn unban_client(&mut self, ip: &str) {
        self.banlist.remove(ip);
        self.banned_until.remove(ip);
        self.rate_limiter.requests.blocking_write().remove(ip);
        info!("Client {} unbanned", ip);
    }

    fn check_release_policy(&self, path: &DebianPath) -> Result<()> {
        if !self.allowed_suites.contains(&path.suite) {
            return Err(anyhow!("Suite '{}' is not allowed", path.suite));
        }

        if let Some(ref component) = path.component {
            if !self.allowed_components.contains(component) {
                return Err(anyhow!("Component '{}' is not allowed", component));
            }
        }

        if let Some(ref arch) = path.architecture {
            if self.denied_architectures.contains(arch) {
                return Err(anyhow!("Architecture '{}' is explicitly denied", arch));
            }
            if !self.allowed_architectures.contains(arch) {
                return Err(anyhow!("Architecture '{}' is not allowed", arch));
            }
        }

        if path.component.is_none() {
            return Ok(());
        }

        Ok(())
    }

    fn check_package_policy(&self, path: &DebianPath) -> Result<()> {
        if let Some(ref component) = path.component {
            if !self.allowed_components.contains(component) {
                return Err(anyhow!("Component '{}' is not allowed", component));
            }
        }

        if let Some(ref filename) = path.filename {
            if let Some(package_name) = self.extract_package_name(filename) {
                if self.denied_packages.contains(&package_name) {
                    return Err(anyhow!("Package '{}' is explicitly denied", package_name));
                }
            }
        }

        Ok(())
    }

    fn extract_package_name(&self, filename: &str) -> Option<String> {
        if filename.ends_with(".deb") {
            let parts: Vec<&str> = filename.split('_').collect();
            if !parts.is_empty() {
                return Some(parts[0].to_string());
            }
        }
        None
    }

    pub fn check_file_size(&self, size_bytes: u64) -> Result<()> {
        let size_mb = size_bytes / (1024 * 1024);
        if size_mb > self.config.limits.max_deb_size_mb {
            return Err(anyhow!(
                "File size {}MB exceeds maximum allowed size {}MB",
                size_mb,
                self.config.limits.max_deb_size_mb
            ));
        }
        Ok(())
    }

    pub fn load_config_from_file(&mut self, config_path: &str) -> Result<()> {
        let config_content = std::fs::read_to_string(config_path)?;
        let config: PolicyConfig = toml::from_str(&config_content)?;

        self.rate_limiter = RateLimiter::new(
            config.limits.max_requests_per_minute_per_ip,
            config.limits.burst_size,
        );

        *self = Self::from_config(config);
        info!("Policy configuration loaded from {}", config_path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_engine_creation() {
        let engine = PolicyEngine::new();
        assert!(engine.allowed_suites.contains("bookworm"));
        assert!(engine.denied_architectures.contains("i386"));
    }

    #[test]
    fn test_allowed_path() {
        let engine = PolicyEngine::new();
        let result = engine.check_path("/debian/dists/bookworm/main/binary-amd64/Packages.gz");
        assert!(result.is_ok());
    }

    #[test]
    fn test_denied_architecture() {
        let engine = PolicyEngine::new();
        let result = engine.check_path("/debian/dists/bookworm/main/binary-i386/Packages.gz");
        assert!(result.is_err());
    }

    #[test]
    fn test_file_size_limit() {
        let engine = PolicyEngine::new();
        assert!(engine.check_file_size(100 * 1024 * 1024).is_ok());
        assert!(engine.check_file_size(600 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_denied_suite() {
        let engine = PolicyEngine::new();
        let result = engine.check_path("/debian/dists/sid/main/binary-amd64/Packages.gz");
        assert!(result.is_err());
    }

    #[test]
    fn test_pool_path() {
        let engine = PolicyEngine::new();
        let result = engine.check_path("/debian/pool/main/a/apt/apt_2.6.1_amd64.deb");
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(5, 5);
        assert!(limiter.check_blocking("127.0.0.1").is_ok());
        assert!(limiter.check_blocking("127.0.0.1").is_ok());
        assert!(limiter.check_blocking("127.0.0.1").is_ok());
        assert!(limiter.check_blocking("127.0.0.1").is_ok());
        assert!(limiter.check_blocking("127.0.0.1").is_ok());
        assert!(limiter.check_blocking("127.0.0.1").is_err());
    }

    #[test]
    fn test_banlist() {
        let mut engine = PolicyEngine::new();
        engine.ban_client("192.168.1.1", Duration::from_secs(10));
        assert!(engine.check_banlist("192.168.1.1").is_err());
        engine.unban_client("192.168.1.1");
        assert!(engine.check_banlist("192.168.1.1").is_ok());
    }
}
