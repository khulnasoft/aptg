use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use crate::mirror::path::{PathParser, DebianPath, PathType};
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
    pub max_request_rate_per_minute: u32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allow: AllowPolicy {
                suites: vec!["bookworm".to_string(), "bullseye".to_string()],
                components: vec!["main".to_string(), "contrib".to_string(), "non-free".to_string()],
                architectures: vec!["amd64".to_string(), "arm64".to_string(), "binary-amd64".to_string()],
            },
            deny: DenyPolicy {
                architectures: vec!["i386".to_string()],
                packages: vec![],
            },
            limits: LimitsPolicy {
                max_deb_size_mb: 500,
                max_request_rate_per_minute: 100,
            },
        }
    }
}

pub struct PolicyEngine {
    config: PolicyConfig,
    allowed_suites: HashSet<String>,
    allowed_components: HashSet<String>,
    allowed_architectures: HashSet<String>,
    denied_architectures: HashSet<String>,
    denied_packages: HashSet<String>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let config = PolicyConfig::default();
        Self::from_config(config)
    }
    
    pub fn from_config(config: PolicyConfig) -> Self {
        let allowed_suites: HashSet<String> = config.allow.suites.iter().cloned().collect();
        let allowed_components: HashSet<String> = config.allow.components.iter().cloned().collect();
        let allowed_architectures: HashSet<String> = config.allow.architectures.iter().cloned().collect();
        let denied_architectures: HashSet<String> = config.deny.architectures.iter().cloned().collect();
        let denied_packages: HashSet<String> = config.deny.packages.iter().cloned().collect();
        
        Self {
            config,
            allowed_suites,
            allowed_components,
            allowed_architectures,
            denied_architectures,
            denied_packages,
        }
    }
    
    pub fn check_request(&self, path: &str, method: &Method) -> bool {
        if method != Method::GET && method != Method::HEAD {
            return false;
        }
        self.check_path(path).is_ok()
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
    
    fn check_release_policy(&self, path: &DebianPath) -> Result<()> {
        // Check suite
        if !self.allowed_suites.contains(&path.suite) {
            return Err(anyhow!("Suite '{}' is not allowed", path.suite));
        }
        
        // Check component if specified
        if let Some(ref component) = path.component {
            if !self.allowed_components.contains(component) {
                return Err(anyhow!("Component '{}' is not allowed", component));
            }
        }
        
        // Check architecture if specified
        if let Some(ref arch) = path.architecture {
            if self.denied_architectures.contains(arch) {
                return Err(anyhow!("Architecture '{}' is explicitly denied", arch));
            }
            if !self.allowed_architectures.contains(arch) {
                return Err(anyhow!("Architecture '{}' is not allowed", arch));
            }
        }
        
        // Allow top-level release files (InRelease, Release, Release.gpg)
        if path.component.is_none() {
            return Ok(());
        }
        
        Ok(())
    }
    
    fn check_package_policy(&self, path: &DebianPath) -> Result<()> {
        // Check component if specified
        if let Some(ref component) = path.component {
            if !self.allowed_components.contains(component) {
                return Err(anyhow!("Component '{}' is not allowed", component));
            }
        }
        
        // Check package name if denied
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
        // Extract package name from .deb filename
        // Example: apt_2.6.1_amd64.deb -> apt
        if filename.ends_with(".deb") {
            let parts: Vec<&str> = filename.split('_').collect();
            if parts.len() >= 1 {
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
        // Default limit is 500MB
        assert!(engine.check_file_size(100 * 1024 * 1024).is_ok()); // 100MB
        assert!(engine.check_file_size(600 * 1024 * 1024).is_err()); // 600MB
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
}
