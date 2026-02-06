use anyhow::Result;
use chrono::{DateTime, Utc, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationInfo {
    pub ip_address: String,
    pub country_code: String,
    pub country_name: String,
    pub city: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: Option<String>,
    pub continent_code: String,
    pub is_in_european_union: bool,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub is_anonymous_proxy: bool,
    pub is_satellite_provider: bool,
}

impl LocationInfo {
    pub fn new(ip: &str, country_code: &str, country_name: &str) -> Self {
        Self {
            ip_address: ip.to_string(),
            country_code: country_code.to_string(),
            country_name: country_name.to_string(),
            city: None,
            region: None,
            postal_code: None,
            latitude: 0.0,
            longitude: 0.0,
            timezone: None,
            continent_code: "".to_string(),
            is_in_european_union: false,
            asn: None,
            organization: None,
            is_anonymous_proxy: false,
            is_satellite_provider: false,
        }
    }

    pub fn with_coordinates(mut self, lat: f64, lon: f64) -> Self {
        self.latitude = lat;
        self.longitude = lon;
        self
    }

    pub fn with_city(mut self, city: &str) -> Self {
        self.city = Some(city.to_string());
        self
    }

    pub fn with_region(mut self, region: &str) -> Self {
        self.region = Some(region.to_string());
        self
    }

    pub fn with_anonymous_proxy(mut self, is_proxy: bool) -> Self {
        self.is_anonymous_proxy = is_proxy;
        self
    }

    pub fn with_timezone(mut self, timezone: &str) -> Self {
        self.timezone = Some(timezone.to_string());
        self
    }

    pub fn with_continent(mut self, continent: &str) -> Self {
        self.continent_code = continent.to_string();
        self
    }

    pub fn is_in_country(&self, country_code: &str) -> bool {
        self.country_code == country_code
    }

    pub fn is_in_region(&self, region: &str) -> bool {
        self.region.as_ref().map_or(false, |r| r.to_lowercase() == region.to_lowercase())
    }

    pub fn is_in_continent(&self, continent_code: &str) -> bool {
        self.continent_code == continent_code
    }

    pub fn is_in_eu(&self) -> bool {
        self.is_in_european_union
    }

    pub fn get_distance_from(&self, other_lat: f64, other_lon: f64) -> f64 {
        // Calculate distance using Haversine formula
        const EARTH_RADIUS_KM: f64 = 6371.0;
        
        let lat1_rad = self.latitude.to_radians();
        let lat2_rad = other_lat.to_radians();
        let delta_lat = lat2_rad - lat1_rad;
        let delta_lon = (other_lon - self.longitude).to_radians();
        
        let a = (delta_lat / 2.0).sin().powi(2) +
            lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
        
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        
        EARTH_RADIUS_KM * c
    }

    pub fn get_timezone_offset(&self) -> Option<i32> {
        // Return timezone offset in hours from UTC
        // This is a simplified version - in practice, you'd use a proper timezone library
        match self.timezone.as_deref() {
            Some("UTC") => Some(0),
            Some("Europe/London") => Some(0),
            Some("Europe/Paris") => Some(1),
            Some("Europe/Berlin") => Some(1),
            Some("Europe/Rome") => Some(1),
            Some("Europe/Spain") => Some(1),
            Some("Europe/Amsterdam") => Some(1),
            Some("Europe/Stockholm") => Some(1),
            Some("Europe/Warsaw") => Some(1),
            Some("America/New_York") => Some(-5),
            Some("America/Chicago") => Some(-6),
            Some("America/Denver") => Some(-7),
            Some("America/Los_Angeles") => Some(-8),
            Some("America/Phoenix") => Some(-7),
            Some("America/Anchorage") => Some(-9),
            Some("Pacific/Auckland") => Some(12),
            Some("Australia/Sydney") => Some(10),
            Some("Asia/Tokyo") => Some(9),
            Some("Asia/Shanghai") => Some(8),
            Some("Asia/Singapore") => Some(8),
            Some("Asia/Dubai") => Some(4),
            Some("Asia/Kolkata") => Some(5),
            _ => None,
        }
    }

    pub fn is_business_hours(&self) -> bool {
        // Simple business hours check (9 AM - 5 PM local time)
        if let Some(offset) = self.get_timezone_offset() {
            let utc_hour = Utc::now().hour() as i32;
            let local_hour = (utc_hour + offset) % 24;
            local_hour >= 9 && local_hour < 17
        } else {
            false
        }
    }

    pub fn get_country_grouping(&self) -> String {
        // Group countries for policy purposes
        match self.country_code.as_str() {
            // North America
            "US" | "CA" | "MX" => "north_america".to_string(),
            // Europe
            "GB" | "DE" | "FR" | "IT" | "ES" | "NL" | "BE" | "AT" | "CH" | "SE" | "NO" | "DK" | "FI" | "PL" | "CZ" | "HU" | "GR" | "PT" | "IE" => "europe".to_string(),
            // Asia Pacific
            "CN" | "JP" | "KR" | "SG" | "AU" | "NZ" | "IN" | "TH" | "MY" | "ID" | "PH" => "asia_pacific".to_string(),
            // South America
            "BR" | "AR" | "CL" | "CO" | "PE" | "VE" | "EC" | "BO" | "UY" | "PY" => "south_america".to_string(),
            // Africa
            "ZA" | "EG" | "NG" | "KE" | "MA" | "TN" | "GH" => "africa".to_string(),
            // Middle East
            "SA" | "AE" | "IL" | "IR" | "IQ" | "JO" | "LB" | "SY" | "TR" => "middle_east".to_string(),
            // Others
            _ => "other".to_string(),
        }
    }

    pub fn get_risk_score(&self) -> u8 {
        // Simple risk scoring based on location
        let mut score = 50; // Base score
        
        // Adjust based on country
        match self.country_code.as_str() {
            // High risk countries
            "CN" | "RU" | "KP" | "IR" => score += 30,
            // Medium risk countries
            "IN" | "BR" | "ID" | "PK" => score += 15,
            // Low risk countries
            "US" | "CA" | "GB" | "DE" | "FR" | "JP" | "AU" => score -= 10,
            _ => {}
        }
        
        // Adjust based on anonymity
        if self.is_anonymous_proxy {
            score += 40;
        }
        
        // Adjust based on satellite provider
        if self.is_satellite_provider {
            score += 20;
        }
        
        // Cap at 100
        score.min(100)
    }

    pub fn get_location_hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.country_code.hash(&mut hasher);
        self.city.hash(&mut hasher);
        self.region.hash(&mut hasher);
        
        format!("{:x}", hasher.finish())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationStats {
    pub total_requests: u64,
    pub country_counts: HashMap<String, u64>,
    pub city_counts: HashMap<String, u64>,
    pub continent_counts: HashMap<String, u64>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl LocationStats {
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            country_counts: HashMap::new(),
            city_counts: HashMap::new(),
            continent_counts: HashMap::new(),
            last_updated: chrono::Utc::now(),
        }
    }

    pub fn record_request(&mut self, location: &LocationInfo) {
        self.total_requests += 1;
        
        *self.country_counts.entry(location.country_code.clone()).or_insert(0) += 1;
        
        if let Some(ref city) = location.city {
            *self.city_counts.entry(city.clone()).or_insert(0) += 1;
        }
        
        *self.continent_counts.entry(location.continent_code.clone()).or_insert(0) += 1;
        
        self.last_updated = chrono::Utc::now();
    }

    pub fn get_top_countries(&self, limit: usize) -> Vec<(&String, &u64)> {
        let mut countries: Vec<_> = self.country_counts.iter().collect();
        countries.sort_by(|a, b| b.1.cmp(a.1));
        countries.into_iter().take(limit).collect()
    }

    pub fn get_top_cities(&self, limit: usize) -> Vec<(&String, &u64)> {
        let mut cities: Vec<_> = self.city_counts.iter().collect();
        cities.sort_by(|a, b| b.1.cmp(a.1));
        cities.into_iter().take(limit).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_creation() {
        let location = LocationInfo::new("8.8.8.8", "US", "United States");
        assert_eq!(location.ip_address, "8.8.8.8");
        assert_eq!(location.country_code, "US");
        assert_eq!(location.country_name, "United States");
        assert!(location.is_in_country("US"));
        assert!(!location.is_in_country("CA"));
    }

    #[test]
    fn test_country_grouping() {
        let us_location = LocationInfo::new("8.8.8.8", "US", "United States");
        assert_eq!(us_location.get_country_grouping(), "north_america");
        
        let de_location = LocationInfo::new("8.8.8.8", "DE", "Germany");
        assert_eq!(de_location.get_country_grouping(), "europe");
        
        let cn_location = LocationInfo::new("8.8.8.8", "CN", "China");
        assert_eq!(cn_location.get_country_grouping(), "asia_pacific");
    }

    #[test]
    fn test_risk_score() {
        let safe_location = LocationInfo::new("8.8.8.8", "US", "United States");
        assert_eq!(safe_location.get_risk_score(), 40);
        
        let risky_location = LocationInfo::new("8.8.8.8", "CN", "China");
        assert_eq!(risky_location.get_risk_score(), 80);
        
        let proxy_location = LocationInfo::new("8.8.8.8", "US", "United States")
            .with_anonymous_proxy(true);
        assert_eq!(proxy_location.get_risk_score(), 80);
    }
}
