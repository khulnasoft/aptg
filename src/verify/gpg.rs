use anyhow::{Result, anyhow};
use std::process::Command;
use std::fs;
use tracing::{info, warn};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpgKeyInfo {
    pub key_id: String,
    pub user_id: String,
    pub creation_date: String,
    pub expiration_date: Option<String>,
    pub fingerprint: String,
    pub trust_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpgVerificationResult {
    pub valid: bool,
    pub key_id: Option<String>,
    pub signature_date: String,
    pub trust_level: String,
    pub error_message: Option<String>,
}

pub struct GpgVerifier {
    keyring_path: String,
}

impl GpgVerifier {
    pub fn new(keyring_path: &str) -> Self {
        Self {
            keyring_path: keyring_path.to_string(),
        }
    }

    pub fn verify_inrelease(&self, inrelease_data: &[u8]) -> Result<GpgVerificationResult> {
        info!("Verifying InRelease file with GPG");
        
        // Write to temporary file
        let temp_path = "/tmp/inrelease_temp";
        fs::write(temp_path, inrelease_data)?;
        
        let output = Command::new("gpg")
            .arg("--verify")
            .arg("--verbose")
            .arg("--keyring")
            .arg(&self.keyring_path)
            .arg(temp_path)
            .output()?;
        
        // Clean up temp file
        let _ = fs::remove_file(temp_path);
        
        self.parse_gpg_output(&output)
    }

    pub fn verify_release_with_sig(&self, release_data: &[u8], signature_data: &[u8]) -> Result<GpgVerificationResult> {
        info!("Verifying Release file with detached signature");
        
        // Write to temporary files
        let release_path = "/tmp/release_temp";
        let sig_path = "/tmp/release_sig_temp";
        
        fs::write(release_path, release_data)?;
        fs::write(sig_path, signature_data)?;
        
        let output = Command::new("gpg")
            .arg("--verify")
            .arg("--verbose")
            .arg("--keyring")
            .arg(&self.keyring_path)
            .arg(sig_path)
            .arg(release_path)
            .output()?;
        
        // Clean up temp files
        let _ = fs::remove_file(release_path);
        let _ = fs::remove_file(sig_path);
        
        self.parse_gpg_output(&output)
    }

    pub fn list_keys(&self) -> Result<Vec<GpgKeyInfo>> {
        info!("Listing GPG keys in keyring");
        
        let output = Command::new("gpg")
            .arg("--list-keys")
            .arg("--with-colons")
            .arg("--keyring")
            .arg(&self.keyring_path)
            .output()?;
        
        self.parse_key_list(&output)
    }

    pub fn import_key(&self, key_data: &[u8]) -> Result<String> {
        info!("Importing GPG key into keyring");
        
        // Write to temporary file
        let temp_path = "/tmp/key_temp.asc";
        fs::write(temp_path, key_data)?;
        
        let output = Command::new("gpg")
            .arg("--import")
            .arg("--verbose")
            .arg("--keyring")
            .arg(&self.keyring_path)
            .arg(temp_path)
            .output()?;
        
        // Clean up temp file
        let _ = fs::remove_file(temp_path);
        
        // Extract key ID from output
        let output_str = String::from_utf8_lossy(&output.stdout);
        if let Some(key_line) = output_str.lines().find(|line| line.contains("imported")) {
            if let Some(key_start) = key_line.find(":") {
                let key_id = key_line[key_start + 1..].trim();
                info!("Successfully imported key: {}", key_id);
                return Ok(key_id.to_string());
            }
        }
        
        Err(anyhow!("Failed to import GPG key"))
    }

    pub fn import_debian_keys(&self) -> Result<()> {
        info!("Importing Debian archive keys");
        
        // Debian archive keys for recent releases
        let debian_keys = vec![
            ("debian-archive-bullseye-automatic", "https://ftp-master.debian.org/keys/archive-keys-10.asc"),
            ("debian-archive-bullseye-security-automatic", "https://ftp-master.debian.org/keys/archive-keys-10.asc"),
            ("debian-archive-bookworm-automatic", "https://ftp-master.debian.org/keys/archive-keys-12.asc"),
            ("debian-archive-bookworm-security-automatic", "https://ftp-master.debian.org/keys/archive-keys-12.asc"),
        ];
        
        let mut imported_keys = Vec::new();
        
        for (key_name, key_url) in debian_keys {
            match self.download_and_import_key(key_url) {
                Ok(key_id) => {
                    info!("Imported Debian key {}: {} ({})", key_name, key_id, key_url);
                    imported_keys.push(key_id);
                }
                Err(e) => {
                    warn!("Failed to import Debian key {}: {} - {}", key_name, key_url, e);
                }
            }
        }
        
        info!("Successfully imported {} Debian archive keys", imported_keys.len());
        Ok(())
    }

    fn download_and_import_key(&self, key_url: &str) -> Result<String> {
        info!("Downloading key from: {}", key_url);
        
        // Download key using curl (or reqwest in async context)
        let output = Command::new("curl")
            .arg("-s")
            .arg(key_url)
            .output()?;
        
        if !output.status.success() {
            return Err(anyhow!("Failed to download key from {}", key_url));
        }
        
        self.import_key(&output.stdout)
    }

    fn parse_gpg_output(&self, output: &std::process::Output) -> Result<GpgVerificationResult> {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);
        
        if output.status.success() {
            // Parse successful verification
            let mut result = GpgVerificationResult {
                valid: true,
                key_id: None,
                signature_date: String::new(),
                trust_level: "ultimate".to_string(),
                error_message: None,
            };
            
            // Extract key information from output
            for line in output_str.lines() {
                if line.contains("using RSA key") {
                    if let Some(key_part) = line.split_whitespace().nth(2) {
                        result.key_id = Some(key_part.trim_end_matches(',').to_string());
                    }
                }
            }
            
            Ok(result)
        } else {
            // Parse error
            let error_msg = if error_str.is_empty() {
                "GPG verification failed".to_string()
            } else {
                error_str.to_string()
            };
            
            Ok(GpgVerificationResult {
                valid: false,
                key_id: None,
                signature_date: String::new(),
                trust_level: "unknown".to_string(),
                error_message: Some(error_msg),
            })
        }
    }

    fn parse_key_list(&self, output: &std::process::Output) -> Result<Vec<GpgKeyInfo>> {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut keys = Vec::new();
        
        for line in output_str.lines() {
            if line.starts_with("pub:") {
                if let Some(key_info) = self.parse_key_line(line) {
                    keys.push(key_info);
                }
            }
        }
        
        Ok(keys)
    }

    fn parse_key_line(&self, line: &str) -> Option<GpgKeyInfo> {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 10 {
            return None;
        }
        
        Some(GpgKeyInfo {
            key_id: parts.get(4).unwrap_or(&"").to_string(),
            user_id: parts.get(9).unwrap_or(&"").to_string(),
            creation_date: parts.get(5).unwrap_or(&"").to_string(),
            expiration_date: if parts.get(6).unwrap_or(&"").is_empty() { None } else { Some(parts[6].to_string()) },
            fingerprint: parts.get(11).unwrap_or(&"").to_string(),
            trust_level: parts.get(1).unwrap_or(&"").to_string(),
        })
    }

    pub fn verify_file_signature(&self, file_path: &str) -> Result<GpgVerificationResult> {
        info!("Verifying signature for file: {}", file_path);
        
        let output = Command::new("gpg")
            .arg("--verify")
            .arg("--verbose")
            .arg("--keyring")
            .arg(&self.keyring_path)
            .arg(file_path)
            .output()?;
        
        self.parse_gpg_output(&output)
    }

    pub fn get_keyring_info(&self) -> Result<KeyringInfo> {
        info!("Getting keyring information");
        
        let output = Command::new("gpg")
            .arg("--list-keys")
            .arg("--with-colons")
            .arg("--keyring")
            .arg(&self.keyring_path)
            .output()?;
        
        self.parse_keyring_info(&output)
    }

    fn parse_keyring_info(&self, output: &std::process::Output) -> Result<KeyringInfo> {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut key_count = 0;
        let mut trusted_keys = 0;
        let mut ultimate_keys = 0;
        
        for line in output_str.lines() {
            if line.starts_with("pub:") {
                key_count += 1;
                if line.contains("u:") {
                    trusted_keys += 1;
                }
                if line.contains("u:") {
                    ultimate_keys += 1;
                }
            }
        }
        
        Ok(KeyringInfo {
            total_keys: key_count,
            trusted_keys,
            ultimate_keys,
            keyring_path: self.keyring_path.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringInfo {
    pub total_keys: usize,
    pub trusted_keys: usize,
    pub ultimate_keys: usize,
    pub keyring_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_gpg_verifier_creation() {
        let verifier = GpgVerifier::new("/tmp/test-keyring.gpg");
        assert_eq!(verifier.keyring_path, "/tmp/test-keyring.gpg");
    }

    #[test]
    fn test_parse_key_line() {
        let verifier = GpgVerifier::new("test.gpg");
        let line = "pub:u:2048:1:1234567890ABCDEF:2023-01-01::e:u:John Doe <johndoe@example.com>:SC:ABCDEF1234567890ABCDEF";
        
        if let Some(key_info) = verifier.parse_key_line(line) {
            assert_eq!(key_info.key_id, "1234567890ABCDEF");
            assert_eq!(key_info.user_id, "John Doe <johndoe@example.com>");
            assert_eq!(key_info.creation_date, "2023-01-01");
            assert_eq!(key_info.fingerprint, "ABCDEF1234567890ABCDEF");
            assert_eq!(key_info.trust_level, "u");
        }
    }
}
