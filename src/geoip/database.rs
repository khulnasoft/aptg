use anyhow::{Result, anyhow};
use maxminddb::Reader;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tracing::{info, warn};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::geoip::location::LocationInfo;
use std::collections::BTreeMap;
// use geoip2::City; // Removed to avoid dependency issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub path: String,
    pub size_bytes: u64,
    pub build_epoch: u32,
    pub database_type: String,
    pub languages: Vec<String>,
    pub last_updated: DateTime<Utc>,
    pub record_count: u64,
}

#[derive(Deserialize, Debug)]
struct ModelCity<'a> {
    #[serde(borrow)]
    city: Option<ModelRecord<'a>>,
    #[serde(borrow)]
    country: Option<ModelCountry<'a>>,
    location: Option<ModelLocation>,
    #[serde(borrow)]
    subdivisions: Option<Vec<ModelRecord<'a>>>,
}

#[derive(Deserialize, Debug)]
struct ModelRecord<'a> {
    #[serde(borrow)]
    names: Option<BTreeMap<&'a str, &'a str>>,
}

#[derive(Deserialize, Debug)]
struct ModelCountry<'a> {
    iso_code: Option<&'a str>,
    #[serde(borrow)]
    names: Option<BTreeMap<&'a str, &'a str>>,
}

#[derive(Deserialize, Debug)]
struct ModelLocation {
    latitude: Option<f64>,
    longitude: Option<f64>,
}

pub struct GeoIpDatabase {
    reader: Reader<Vec<u8>>,
    info: DatabaseInfo,
}

impl GeoIpDatabase {
    pub fn new(database_path: &str) -> Result<Self> {
        info!("Loading GeoIP2 database from: {}", database_path);
        
        let mut file = File::open(database_path)
            .map_err(|e| anyhow!("Failed to open GeoIP2 database file {}: {}", database_path, e))?;
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| anyhow!("Failed to read GeoIP2 database file {}: {}", database_path, e))?;
        
        let reader = Reader::from_source(buffer)
            .map_err(|e| anyhow!("Failed to parse GeoIP2 database: {}", e))?;
        
        let info = Self::extract_database_info(&reader, database_path)?;
        
        info!("GeoIP2 database loaded successfully");
        info!("  Type: {}", info.database_type);
        info!("  Size: {} bytes", info.size_bytes);
        info!("  Records: {}", info.record_count);
        info!("  Languages: {:?}", info.languages);
        
        Ok(Self { reader, info })
    }

    pub fn lookup(&self, ip_address: &str) -> Result<Option<LocationInfo>> {
        let ip: std::net::IpAddr = ip_address.parse()
            .map_err(|e| anyhow!("Invalid IP address {}: {}", ip_address, e))?;
        
        match self.reader.lookup::<ModelCity>(ip) {
            Ok(city) => {
                let iso_code = city.country.as_ref()
                    .and_then(|c| c.iso_code)
                    .unwrap_or("Unknown");
                
                let country_name = city.country.as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| *s) // Map &&str to &str
                    .unwrap_or("Unknown");

                let location = LocationInfo::new(ip_address, iso_code, country_name);
                
                let lat = city.location.as_ref().and_then(|l| l.latitude).unwrap_or(0.0);
                let lon = city.location.as_ref().and_then(|l| l.longitude).unwrap_or(0.0);
                
                let city_name = city.city.as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| *s)
                    .unwrap_or("Unknown");
                
                let region_name = city.subdivisions.as_ref()
                    .and_then(|v| v.first())
                    .and_then(|s| s.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| *s)
                    .unwrap_or("Unknown");

                Ok(Some(location
                    .with_coordinates(lat, lon)
                    .with_city(city_name)
                    .with_region(region_name)))
            }
            Err(_) => Ok(None),
        }
    }

    pub fn get_info(&self) -> &DatabaseInfo {
        &self.info
    }

    pub fn is_valid(&self) -> bool {
        // Check if database is not too old (e.g., more than 30 days)
        let days_old = Utc::now().signed_duration_since(self.info.last_updated).num_days();
        days_old < 30
    }

    fn extract_database_info(reader: &Reader<Vec<u8>>, path: &str) -> Result<DatabaseInfo> {
        let metadata = &reader.metadata;
        let path_obj = Path::new(path);
        
        let size_bytes = path_obj.metadata()
            .map(|m| m.len())
            .unwrap_or(0);
        
        Ok(DatabaseInfo {
            path: path.to_string(),
            size_bytes,
            build_epoch: metadata.build_epoch as u32,
            database_type: "GeoIP2-City".to_string(),
            languages: metadata.languages.iter().map(|l| l.to_string()).collect(),
            last_updated: Utc::now(), // In a real implementation, you'd parse this from metadata
            record_count: 0, // This would need to be calculated or stored separately
        })
    }

    pub fn reload(&mut self) -> Result<()> {
        info!("Reloading GeoIP2 database");
        
        let new_db = Self::new(&self.info.path)?;
        *self = new_db;
        
        info!("GeoIP2 database reloaded successfully");
        Ok(())
    }

    pub fn validate_database(&self) -> Result<()> {
        if !Path::new(&self.info.path).exists() {
            return Err(anyhow!("GeoIP2 database file does not exist: {}", self.info.path));
        }
        
        if !self.is_valid() {
            warn!("GeoIP2 database is old ({} days), consider updating", 
                Utc::now().signed_duration_since(self.info.last_updated).num_days());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_database_creation() {
        // This test would require a real GeoIP2 database file
        // For now, we'll just test the error handling
        let result = GeoIpDatabase::new("/nonexistent/database.mmdb");
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_parsing() {
        let db = GeoIpDatabase::new("/nonexistent/database.mmdb");
        assert!(db.is_err());
        
        // Test valid IP parsing
        let ip = "8.8.8.8";
        let parsed: Result<std::net::IpAddr, _> = ip.parse();
        assert!(parsed.is_ok());
    }
}
