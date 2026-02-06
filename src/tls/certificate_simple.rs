use anyhow::{Result, anyhow};
use openssl::x509::X509;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::asn1::Asn1Time;
use std::fs;
use tracing::info;

pub struct CertificateManager {
    cert_path: String,
    key_path: String,
}

impl CertificateManager {
    pub fn new(cert_path: String, key_path: String) -> Self {
        Self {
            cert_path,
            key_path,
        }
    }

    pub fn load_certificate(&self) -> Result<X509> {
        info!("Loading certificate from: {}", self.cert_path);
        
        let cert_data = fs::read(&self.cert_path)
            .map_err(|e| anyhow!("Failed to read certificate file: {}", e))?;
        
        let cert = X509::from_pem(&cert_data)
            .map_err(|e| anyhow!("Failed to parse certificate PEM: {}", e))?;
        
        info!("Certificate loaded successfully");
        Ok(cert)
    }

    pub fn load_private_key(&self) -> Result<PKey<openssl::pkey::Private>> {
        info!("Loading private key from: {}", self.key_path);
        
        let key_data = fs::read(&self.key_path)
            .map_err(|e| anyhow!("Failed to read private key file: {}", e))?;
        
        let key = PKey::private_key_from_pem(&key_data)
            .map_err(|e| anyhow!("Failed to parse private key PEM: {}", e))?;
        
        info!("Private key loaded successfully");
        Ok(key)
    }

    pub fn generate_self_signed_cert(common_name: &str, cert_path: &str, key_path: &str) -> Result<()> {
        info!("Generating self-signed certificate for CN: {}", common_name);
        
        // Generate RSA private key
        let rsa = Rsa::generate(2048)?;
        let private_key = PKey::from_rsa(rsa)?;
        
        // Create certificate
        let mut builder = openssl::x509::X509::builder()?;
        builder.set_version(2)?;
        
        // Set serial number
        let serial = openssl::bn::BigNum::from_u32(1)?;
        let serial_asn1 = openssl::asn1::Asn1Integer::from_bn(&serial)?;
        builder.set_serial_number(&serial_asn1)?;
        
        // Set validity period (1 year)
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        
        // Set subject and issuer (self-signed)
        let mut name_builder = openssl::x509::X509Name::builder()?;
        name_builder.append_entry_by_text("CN", common_name)?;
        let name = name_builder.build();
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        
        // Set public key
        builder.set_pubkey(&private_key)?;
        
        // Add extensions
        let _context = builder.x509v3_context(None, None);
        builder.append_extension(openssl::x509::extension::BasicConstraints::new().build().unwrap())?;
        builder.append_extension(openssl::x509::extension::KeyUsage::new().digital_signature().key_encipherment().build().unwrap())?;
        builder.append_extension(openssl::x509::extension::ExtendedKeyUsage::new().server_auth().build().unwrap())?;
        
        // Sign certificate
        builder.sign(&private_key, openssl::hash::MessageDigest::sha256())?;
        let certificate = builder.build();
        
        // Save certificate and private key
        fs::write(cert_path, certificate.to_pem()?)?;
        fs::write(key_path, private_key.private_key_to_pem_pkcs8()?)?;
        
        info!("Self-signed certificate generated successfully");
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CertificateInfo {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub sha256_fingerprint: String,
}
