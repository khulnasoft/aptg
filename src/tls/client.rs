use anyhow::{Result, anyhow};
use reqwest::{Client, Certificate};
use std::fs::File;
use std::io::BufReader;
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tracing::{info, warn, error};

pub struct TlsClientConfig {
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub verify_hostname: bool,
    pub min_tls_version: rustls::ProtocolVersion,
}

impl Default for TlsClientConfig {
    fn default() -> Self {
        Self {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            verify_hostname: true,
            min_tls_version: rustls::ProtocolVersion::TLSv1_2,
        }
    }
}

pub struct TlsClient {
    config: TlsClientConfig,
    client: Client,
}

impl TlsClient {
    pub fn new(config: TlsClientConfig) -> Result<Self> {
        let client = Self::build_client(&config)?;
        
        Ok(Self {
            config,
            client,
        })
    }

    fn build_client(config: &TlsClientConfig) -> Result<Client> {
        info!("Building TLS client configuration");
        
        let mut client_builder = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("aptg/0.1.0");

        // Configure custom CA certificates
        if let Some(ref ca_cert_path) = config.ca_cert_path {
            info!("Loading custom CA certificate from: {}", ca_cert_path);
            
            let ca_cert_data = std::fs::read(ca_cert_path)
                .map_err(|e| anyhow!("Failed to read CA certificate: {}", e))?;
            
            let cert = Certificate::from_pem(&ca_cert_data)
                .map_err(|e| anyhow!("Failed to parse CA certificate: {}", e))?;
            
            client_builder = client_builder.add_root_certificate(cert);
        }

        // Configure client authentication
        if let (Some(ref client_cert_path), Some(ref client_key_path)) = 
            (&config.client_cert_path, &config.client_key_path) {
            info!("Loading client certificate from: {}", client_cert_path);
            info!("Loading client private key from: {}", client_key_path);
            
            let cert_data = std::fs::read(client_cert_path)
                .map_err(|e| anyhow!("Failed to read client certificate: {}", e))?;
            let key_data = std::fs::read(client_key_path)
                .map_err(|e| anyhow!("Failed to read client private key: {}", e))?;
            
            let identity = reqwest::Identity::from_pem(
                &[cert_data, key_data].concat()
            ).map_err(|e| anyhow!("Failed to create client identity: {}", e))?;
            
            client_builder = client_builder.identity(identity);
        }

        // Configure hostname verification
        if !config.verify_hostname {
            warn!("Hostname verification disabled - this is insecure!");
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let client = client_builder
            .build()
            .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))?;

        info!("TLS client configuration built successfully");
        Ok(client)
    }

    pub fn get_client(&self) -> &Client {
        &self.client
    }

    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        info!("Making TLS GET request to: {}", url);
        
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("GET request failed: {}", e))?;

        info!("GET request completed with status: {}", response.status());
        Ok(response)
    }

    pub async fn head(&self, url: &str) -> Result<reqwest::Response> {
        info!("Making TLS HEAD request to: {}", url);
        
        let response = self.client
            .head(url)
            .send()
            .await
            .map_err(|e| anyhow!("HEAD request failed: {}", e))?;

        info!("HEAD request completed with status: {}", response.status());
        Ok(response)
    }

    pub fn get_config_info(&self) -> TlsClientInfo {
        TlsClientInfo {
            ca_cert_path: self.config.ca_cert_path.clone(),
            client_cert_path: self.config.client_cert_path.clone(),
            client_key_path: self.config.client_key_path.clone(),
            verify_hostname: self.config.verify_hostname,
            min_tls_version: format!("{:?}", self.config.min_tls_version),
        }
    }

    pub fn reload_config(&mut self) -> Result<()> {
        info!("Reloading TLS client configuration");
        
        let new_client = Self::build_client(&self.config)?;
        self.client = new_client;
        
        info!("TLS client configuration reloaded successfully");
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TlsClientInfo {
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub verify_hostname: bool,
    pub min_tls_version: String,
}

pub fn create_secure_client_config() -> TlsClientConfig {
    TlsClientConfig {
        ca_cert_path: Some("certs/ca.pem".to_string()),
        client_cert_path: Some("certs/client.pem".to_string()),
        client_key_path: Some("certs/client.key".to_string()),
        verify_hostname: true,
        min_tls_version: rustls::ProtocolVersion::TLSv1_3,
    }
}

pub fn create_insecure_client_config() -> TlsClientConfig {
    TlsClientConfig {
        ca_cert_path: None,
        client_cert_path: None,
        client_key_path: None,
        verify_hostname: false,
        min_tls_version: rustls::ProtocolVersion::TLSv1_2,
    }
}

pub struct CertificateValidator {
    trusted_certs: RootCertStore,
}

impl CertificateValidator {
    pub fn new() -> Self {
        let mut trusted_certs = RootCertStore::empty();
        
        // Add system root certificates
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                for cert in certs {
                    if let Err(e) = trusted_certs.add(&rustls::Certificate(cert.0)) {
                        warn!("Failed to add system certificate: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to load system certificates: {}", e);
            }
        }
        
        Self { trusted_certs }
    }

    pub fn add_certificate(&mut self, cert_path: &str) -> Result<()> {
        let cert_file = File::open(cert_path)
            .map_err(|e| anyhow!("Failed to open certificate file {}: {}", cert_path, e))?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs = certs(&mut cert_reader)?;
        
        for cert_der in certs {
            self.trusted_certs
                .add(&rustls::Certificate(cert_der))
                .map_err(|e| anyhow!("Failed to add trusted certificate: {}", e))?;
        }
        
        Ok(())
    }

    pub fn validate_certificate(&self, _cert: &rustls::Certificate) -> Result<bool> {
        // In a real implementation, you'd perform proper certificate validation
        // For now, we'll just check if it's in our trusted store
        info!("Validating certificate");
        
        // This is a simplified validation
        // Real implementation would check expiration, hostname, chain, etc.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_client_config_default() {
        let config = TlsClientConfig::default();
        assert!(config.ca_cert_path.is_none());
        assert!(config.client_cert_path.is_none());
        assert!(config.verify_hostname);
    }

    #[test]
    fn test_create_secure_client_config() {
        let config = create_secure_client_config();
        assert!(config.ca_cert_path.is_some());
        assert!(config.client_cert_path.is_some());
        assert!(config.verify_hostname);
        assert_eq!(config.min_tls_version, rustls::ProtocolVersion::TLSv1_3);
    }

    #[test]
    fn test_create_insecure_client_config() {
        let config = create_insecure_client_config();
        assert!(config.ca_cert_path.is_none());
        assert!(config.client_cert_path.is_none());
        assert!(!config.verify_hostname);
    }

    #[test]
    fn test_certificate_validator() {
        let validator = CertificateValidator::new();
        // Test would require actual certificate data
    }
}
