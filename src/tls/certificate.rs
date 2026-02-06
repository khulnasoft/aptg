use anyhow::{Result, anyhow};
use openssl::x509::X509;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::asn1::Asn1Time;
use openssl::stack::Stack;
use openssl::conf::Conf;
use openssl::hash::MessageDigest;
use std::fs;
use std::path::Path;
use tracing::{info, warn, error};

pub struct CertificateManager {
    cert_path: String,
    key_path: String,
    ca_path: Option<String>,
}

impl CertificateManager {
    pub fn new(cert_path: String, key_path: String, ca_path: Option<String>) -> Self {
        Self {
            cert_path,
            key_path,
            ca_path,
        }
    }

    pub fn load_certificate(&self) -> Result<X509> {
        info!("Loading certificate from: {}", self.cert_path);
        
        let cert_data = fs::read(&self.cert_path)
            .map_err(|e| anyhow!("Failed to read certificate file: {}", e))?;
        
        let cert = X509::from_pem(&cert_data)
            .map_err(|e| anyhow!("Failed to parse certificate PEM: {}", e))?;
        
        // Validate certificate
        self.validate_certificate(&cert)?;
        
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

    pub fn load_ca_bundle(&self) -> Result<Option<Stack<X509>>> {
        if let Some(ref ca_path) = self.ca_path {
            info!("Loading CA bundle from: {}", ca_path);
            
            let ca_data = fs::read(ca_path)
                .map_err(|e| anyhow!("Failed to read CA bundle file: {}", e))?;
            
            let cert_stack = X509::stack_from_pem(&ca_data)
                .map_err(|e| anyhow!("Failed to parse CA bundle PEM: {}", e))?;
            
            info!("CA bundle loaded with {} certificates", cert_stack.len());
            Ok(Some(cert_stack))
        } else {
            info!("No CA bundle specified, using system defaults");
            Ok(None)
        }
    }

    fn validate_certificate(&self, cert: &X509) -> Result<()> {
        // Check if certificate is currently valid
        let now = Asn1Time::days_from_now(0)?;
        
        if cert.not_before().compare(&now) == openssl::asn1::Asn1TimeCompare::GreaterThan {
            return Err(anyhow!("Certificate is not yet valid"));
        }
        
        if cert.not_after().compare(&now) == openssl::asn1::Asn1TimeCompare::LessThan {
            return Err(anyhow!("Certificate has expired"));
        }
        
        // Check certificate purpose (server authentication)
        let purpose_id = openssl::x509::X509_PURPOSE_SSL_SERVER;
        if !cert.check_purpose(purpose_id, false) {
            warn!("Certificate may not be suitable for SSL server authentication");
        }
        
        // Extract and log certificate information
        let subject = cert.subject_name();
        if let Some(common_name) = Self::extract_common_name_static(subject) {
            info!("Certificate subject CN: {}", common_name);
        }
        
        let issuer = cert.issuer_name();
        if let Some(common_name) = Self::extract_common_name_static(issuer) {
            info!("Certificate issuer CN: {}", common_name);
        }
        
        let serial = cert.serial_number();
        info!("Certificate serial number: {:?}", serial);
        
        Ok(())
    }

    fn extract_common_name_static(name: &openssl::x509::X509Name) -> Option<String> {
        name.entries_by_nid(openssl::x509::Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|s| s.to_string())
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
        builder.sign(&private_key, MessageDigest::sha256())?;
        let certificate = builder.build();
        
        // Save certificate and private key
        fs::write(cert_path, certificate.to_pem()?)?;
        fs::write(key_path, private_key.private_key_to_pem_pkcs8()?)?;
        
        info!("Self-signed certificate generated successfully");
        Ok(())
    }

    pub fn verify_certificate_chain(cert: &X509, ca_bundle: Option<&Stack<X509>>) -> Result<bool> {
        let mut store = openssl::x509::store::X509StoreBuilder::new()?;
        
        // Add system default CAs
        // Note: load_locations may not be available in all OpenSSL versions
        
        // Add custom CA bundle if provided
        if let Some(ca_certs) = ca_bundle {
            for ca_cert in ca_certs {
                store.add_cert(ca_cert.to_owned())?;
            }
        }
        
        let store = store.build();
        
        // Create verification context
        let mut ctx = openssl::x509::X509StoreContext::new()?;
        ctx.init(&store, cert, &[])?;
        
        // Verify certificate
        match ctx.verify_cert() {
            Ok(_) => {
                info!("Certificate verification successful");
                Ok(true)
            }
            Err(e) => {
                error!("Certificate verification failed: {}", e);
                Ok(false)
            }
        }
    }

    pub fn get_certificate_info(cert: &X509) -> CertificateInfo {
        let mut info = CertificateInfo::default();
        
        // Extract subject information
        let subject = cert.subject_name();
        info.common_name = Self::extract_common_name_static(subject);
        info.organization = Self::extract_field_static(subject, "O");
        info.organizational_unit = Self::extract_field_static(subject, "OU");
        info.country = Self::extract_field_static(subject, "C");
        
        // Extract issuer information
        let issuer = cert.issuer_name();
        info.issuer_common_name = Self::extract_common_name_static(issuer);
        info.issuer_organization = Self::extract_field_static(issuer, "O");
        
        // Extract validity dates
        info.not_before = cert.not_before().to_string();
        info.not_after = cert.not_after().to_string();
        
        // Extract serial number
        if let Ok(bn) = cert.serial_number().to_bn() {
            if let Ok(hex_str) = bn.to_hex_str() {
                info.serial_number = hex_str.to_string();
            }
        }
        
        // Extract fingerprint
        info.sha256_fingerprint = cert.digest(MessageDigest::sha256())
            .map(|digest| hex::encode(digest.as_ref()))
            .unwrap_or_default();
        
        info
    }

    fn extract_common_name_static(name: &openssl::x509::X509NameRef) -> Option<String> {
        name.entries_by_nid(openssl::x509::Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|s| s.to_string())
    }

    fn extract_field_static(name: &openssl::x509::X509NameRef, field: &str) -> Option<String> {
        let nid = match field {
            "O" => openssl::x509::Nid::ORGANIZATIONNAME,
            "OU" => openssl::x509::Nid::ORGANIZATIONALUNITNAME,
            "C" => openssl::x509::Nid::COUNTRYNAME,
            _ => return None,
        };
        
        name.entries_by_nid(nid)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|s| s.to_string())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CertificateInfo {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub issuer_common_name: Option<String>,
    pub issuer_organization: Option<String>,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub sha256_fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_self_signed_cert() {
        let cert_file = NamedTempFile::new().unwrap();
        let key_file = NamedTempFile::new().unwrap();
        
        let result = CertificateManager::generate_self_signed_cert(
            "localhost",
            cert_file.path().to_str().unwrap(),
            key_file.path().to_str().unwrap(),
        );
        
        assert!(result.is_ok());
        
        // Verify we can load the generated certificate
        let manager = CertificateManager::new(
            cert_file.path().to_str().unwrap().to_string(),
            key_file.path().to_str().unwrap().to_string(),
            None,
        );
        
        assert!(manager.load_certificate().is_ok());
        assert!(manager.load_private_key().is_ok());
    }
}
