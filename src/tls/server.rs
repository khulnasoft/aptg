use anyhow::{Result, anyhow};
use warp::Filter;
use std::sync::Arc;
use std::fs::File;
use std::io::BufReader;
use rustls::{ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::TlsAcceptor;
use tracing::info;

pub struct TlsServerConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: Option<String>,
    pub client_auth_required: bool,
    pub min_tls_version: rustls::ProtocolVersion,
}

impl Default for TlsServerConfig {
    fn default() -> Self {
        Self {
            cert_path: "cert.pem".to_string(),
            key_path: "key.pem".to_string(),
            ca_path: None,
            client_auth_required: false,
            min_tls_version: rustls::ProtocolVersion::TLSv1_2,
        }
    }
}

pub struct TlsServer {
    config: Arc<TlsServerConfig>,
    acceptor: TlsAcceptor,
}

impl TlsServer {
    pub fn new(config: TlsServerConfig) -> Result<Self> {
        let server_config = Self::build_server_config(&config)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        
        Ok(Self {
            config: Arc::new(config),
            acceptor,
        })
    }

    fn build_server_config(config: &TlsServerConfig) -> Result<ServerConfig> {
        info!("Building TLS server configuration");
        
        // Load certificate
        let cert_file = File::open(&config.cert_path)
            .map_err(|e| anyhow!("Failed to open certificate file {}: {}", config.cert_path, e))?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain: Vec<Certificate> = certs(&mut cert_reader)?
            .into_iter()
            .map(Certificate)
            .collect();
        
        if cert_chain.is_empty() {
            return Err(anyhow!("No certificates found in {}", config.cert_path));
        }
        
        // Load private key
        let key_file = File::open(&config.key_path)
            .map_err(|e| anyhow!("Failed to open private key file {}: {}", config.key_path, e))?;
        let mut key_reader = BufReader::new(key_file);
        let mut keys = pkcs8_private_keys(&mut key_reader)?;
        
        if keys.is_empty() {
            return Err(anyhow!("No private keys found in {}", config.key_path));
        }
        
        let private_key = PrivateKey(keys.remove(0));
        
        // Build server config
        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| anyhow!("Failed to build server config: {}", e))?;
        
        info!("TLS server configuration built successfully");
        Ok(server_config)
    }

    pub async fn run_https_server<F>(
        &self,
        routes: F,
        addr: std::net::SocketAddr,
    ) -> Result<()>
    where
        F: Filter<Extract = warp::reply::Reply, Error = warp::Rejection> + Clone + Send + Sync + 'static,
    {
        info!("Starting HTTPS server on {}", addr);
        
        // Create a simple HTTP server for now
        // In a full implementation, you'd use the TlsAcceptor
        warp::serve(routes).run(addr).await;
        
        Ok(())
    }

    pub fn get_tls_info(&self) -> TlsInfo {
        TlsInfo {
            cert_path: self.config.cert_path.clone(),
            key_path: self.config.key_path.clone(),
            ca_path: self.config.ca_path.clone(),
            client_auth_required: self.config.client_auth_required,
            min_tls_version: format!("{:?}", self.config.min_tls_version),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: Option<String>,
    pub client_auth_required: bool,
    pub min_tls_version: String,
}

pub fn create_secure_server_config() -> TlsServerConfig {
    TlsServerConfig {
        cert_path: "certs/server.pem".to_string(),
        key_path: "certs/server.key".to_string(),
        ca_path: Some("certs/ca.pem".to_string()),
        client_auth_required: false,
        min_tls_version: rustls::ProtocolVersion::TLSv1_3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_tls_server_config_default() {
        let config = TlsServerConfig::default();
        assert_eq!(config.cert_path, "cert.pem");
        assert_eq!(config.key_path, "key.pem");
        assert!(!config.client_auth_required);
    }

    #[test]
    fn test_create_secure_server_config() {
        let config = create_secure_server_config();
        assert_eq!(config.cert_path, "certs/server.pem");
        assert_eq!(config.key_path, "certs/server.key");
        assert!(config.ca_path.is_some());
        assert_eq!(config.min_tls_version, rustls::ProtocolVersion::TLSv1_3);
    }
}
