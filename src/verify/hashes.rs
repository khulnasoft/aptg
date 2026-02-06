use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use tracing::{info, error};

pub struct HashVerifier;

impl HashVerifier {
    pub fn verify_package_hash(data: &[u8], expected_hash: &str) -> Result<bool> {
        info!("Verifying SHA256 hash for package data");
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        let calculated_hash = format!("{:x}", hasher.finalize());
        
        if calculated_hash == expected_hash {
            info!("Hash verification successful");
            Ok(true)
        } else {
            error!("Hash mismatch: expected {}, got {}", expected_hash, calculated_hash);
            Err(anyhow!("SHA256 hash verification failed"))
        }
    }
    
    pub fn parse_release_hashes(release_content: &str) -> Result<HashMap<String, String>> {
        info!("Parsing hashes from Release file");
        
        let mut hashes = HashMap::new();
        let mut in_hashes_section = false;
        
        for line in release_content.lines() {
            if line.starts_with("SHA256:") {
                in_hashes_section = true;
                continue;
            }
            
            if line.is_empty() || line.starts_with("MD5Sum:") || line.starts_with("SHA1:") {
                in_hashes_section = false;
                continue;
            }
            
            if in_hashes_section {
                // SHA256 format: hash size filename
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let hash = parts[0].to_string();
                    let filename = parts[2].to_string();
                    hashes.insert(filename, hash);
                }
            }
        }
        
        info!("Parsed {} hash entries", hashes.len());
        Ok(hashes)
    }
    
    pub fn verify_file_against_release(
        file_data: &[u8], 
        filename: &str, 
        release_hashes: &HashMap<String, String>
    ) -> Result<bool> {
        if let Some(expected_hash) = release_hashes.get(filename) {
            Self::verify_package_hash(file_data, expected_hash)
        } else {
            Err(anyhow!("No hash found for file: {}", filename))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_verification() {
        let data = b"test data";
        let hash = "916f0023a0d5e5904614e65e77b3818a6d5e7e1a5b5c5e5e5e5e5e5e5e5e5e5e5";
        
        // This will fail since we're using fake hash, but tests the structure
        let result = HashVerifier::verify_package_hash(data, hash);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_release_hash_parsing() {
        let release_content = r#"
SHA256:
abc123 1024 main/binary-amd64/Packages
def456 2048 main/binary-amd64/Packages.gz
"#;
        
        let hashes = HashVerifier::parse_release_hashes(release_content).unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes.get("main/binary-amd64/Packages"), Some(&"abc123".to_string()));
    }
}
