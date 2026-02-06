use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};


use tracing::{info, warn, error};
use crate::geoip::database::GeoIpDatabase;
use crate::geoip::location::LocationInfo;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoPolicy {
    pub enabled: bool,
    pub database_path: String,
    pub rules: Vec<GeoRule>,
    pub default_action: GeoAction,
    pub update_interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoRule {
    pub name: String,
    pub condition: GeoCondition,
    pub action: GeoAction,
    pub priority: u8,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GeoCondition {
    CountryCode { codes: Vec<String> },
    Continent { codes: Vec<String> },
    Region { regions: Vec<String> },
    City { cities: Vec<String> },
    CountryGroup { groups: Vec<String> },
    RiskScore { min: Option<u8>, max: Option<u8> },
    Distance { latitude: f64, longitude: f64, radius_km: f64 },
    Timezone { zones: Vec<String> },
    BusinessHours { enabled: bool },
    AnonymousProxy { blocked: bool },
    SatelliteProvider { blocked: bool },
    Asn { ranges: Vec<AsnRange> },
    Custom { field: String, operator: String, value: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GeoAction {
    Allow,
    Deny,
    RateLimit { requests_per_minute: u32 },
    LogOnly,
    Redirect { url: String },
}

impl fmt::Display for GeoAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeoAction::Allow => write!(f, "Allow"),
            GeoAction::Deny => write!(f, "Deny"),
            GeoAction::RateLimit { requests_per_minute } => write!(f, "RateLimit({} req/min)", requests_per_minute),
            GeoAction::LogOnly => write!(f, "LogOnly"),
            GeoAction::Redirect { url } => write!(f, "Redirect({})", url),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub action: GeoAction,
    pub rule_name: Option<String>,
    pub location: LocationInfo,
    pub reason: String,
}

pub struct GeoPolicyEngine {
    database: Option<GeoIpDatabase>,
    policy: GeoPolicy,
}

impl GeoPolicyEngine {
    pub fn new(policy: GeoPolicy) -> Self {
        let database = if policy.enabled {
            match GeoIpDatabase::new(&policy.database_path) {
                Ok(db) => Some(db),
                Err(e) => {
                    error!("Failed to load GeoIP database: {}", e);
                    warn!("GeoIP policy will be disabled");
                    None
                }
            }
        } else {
            None
        };

        Self {
            database,
            policy,
        }
    }

    pub fn check_request(&self, ip_address: &str, _path: &str) -> Result<PolicyResult> {
        if !self.policy.enabled {
            return Ok(PolicyResult {
                action: self.policy.default_action.clone(),
                rule_name: None,
                location: LocationInfo::new(ip_address, "Unknown", "Unknown"),
                reason: "GeoIP policy disabled".to_string(),
            });
        }

        let database = self.database.as_ref()
            .ok_or_else(|| anyhow!("GeoIP database not available"))?;

        let location = database.lookup(ip_address)?
            .unwrap_or_else(|| LocationInfo::new(ip_address, "Unknown", "Unknown"));

        // Check rules in priority order
        let mut matching_rule = None;
        let mut highest_priority = 0;

        for rule in &self.policy.rules {
            if !rule.enabled {
                continue;
            }

            if self.evaluate_condition(&rule.condition, &location) {
                if rule.priority > highest_priority {
                    matching_rule = Some(rule);
                    highest_priority = rule.priority;
                }
            }
        }

        let (action, rule_name, reason) = if let Some(rule) = matching_rule {
            (rule.action.clone(), Some(rule.name.clone()), format!("Matched rule: {}", rule.name))
        } else {
            (self.policy.default_action.clone(), None, "No matching rule".to_string())
        };

        info!("GeoIP policy check for {}: {} - {}", ip_address, action, reason);

        Ok(PolicyResult {
            action,
            rule_name,
            location,
            reason,
        })
    }

    fn evaluate_condition(&self, condition: &GeoCondition, location: &LocationInfo) -> bool {
        match condition {
            GeoCondition::CountryCode { codes } => {
                codes.contains(&location.country_code)
            }
            GeoCondition::Continent { codes } => {
                codes.contains(&location.continent_code)
            }
            GeoCondition::Region { regions } => {
                if let Some(ref region) = location.region {
                    regions.iter().any(|r| r.to_lowercase() == region.to_lowercase())
                } else {
                    false
                }
            }
            GeoCondition::City { cities } => {
                if let Some(ref city) = location.city {
                    cities.iter().any(|c| c.to_lowercase() == city.to_lowercase())
                } else {
                    false
                }
            }
            GeoCondition::CountryGroup { groups } => {
                groups.contains(&location.get_country_grouping())
            }
            GeoCondition::RiskScore { min, max } => {
                let score = location.get_risk_score();
                min.map_or(true, |m| score >= m) && max.map_or(true, |m| score <= m)
            }
            GeoCondition::Distance { latitude, longitude, radius_km } => {
                location.get_distance_from(*latitude, *longitude) <= *radius_km
            }
            GeoCondition::Timezone { zones } => {
                if let Some(ref timezone) = location.timezone {
                    zones.contains(timezone)
                } else {
                    false
                }
            }
            GeoCondition::BusinessHours { enabled } => {
                *enabled == location.is_business_hours()
            }
            GeoCondition::AnonymousProxy { blocked } => {
                *blocked == location.is_anonymous_proxy
            }
            GeoCondition::SatelliteProvider { blocked } => {
                *blocked == location.is_satellite_provider
            }
            GeoCondition::Asn { ranges } => {
                if let Some(asn) = location.asn {
                    ranges.iter().any(|range| asn >= range.start && asn <= range.end)
                } else {
                    false
                }
            }
            GeoCondition::Custom { field, operator, value } => {
                self.evaluate_custom_field(field, operator, value, location)
            }
        }
    }

    fn evaluate_custom_field(&self, field: &str, operator: &str, value: &str, location: &LocationInfo) -> bool {
        let field_value = match field {
            "country_code" => location.country_code.clone(),
            "country_name" => location.country_name.clone(),
            "city" => location.city.clone().unwrap_or_default(),
            "region" => location.region.clone().unwrap_or_default(),
            "postal_code" => location.postal_code.clone().unwrap_or_default(),
            "timezone" => location.timezone.clone().unwrap_or_default(),
            "continent_code" => location.continent_code.clone(),
            "country_grouping" => location.get_country_grouping(),
            "risk_score" => location.get_risk_score().to_string(),
            _ => return false,
        };

        match operator {
            "equals" => field_value == value,
            "not_equals" => field_value != value,
            "contains" => field_value.contains(value),
            "starts_with" => field_value.starts_with(value),
            "ends_with" => field_value.ends_with(value),
            "gt" => field_value.parse::<f64>().map(|v| v > value.parse().unwrap_or(0.0)).unwrap_or(false),
            "lt" => field_value.parse::<f64>().map(|v| v < value.parse().unwrap_or(0.0)).unwrap_or(false),
            "ge" => field_value.parse::<f64>().map(|v| v >= value.parse().unwrap_or(0.0)).unwrap_or(false),
            "le" => field_value.parse::<f64>().map(|v| v <= value.parse().unwrap_or(0.0)).unwrap_or(false),
            _ => false,
        }
    }

    pub fn reload_database(&mut self) -> Result<()> {
        if let Some(ref mut database) = self.database {
            database.reload()?;
            info!("GeoIP database reloaded successfully");
        }
        Ok(())
    }

    pub fn validate_database(&self) -> Result<()> {
        if let Some(ref database) = self.database {
            database.validate_database()?;
        }
        Ok(())
    }

    pub fn get_database_info(&self) -> Option<&crate::geoip::database::DatabaseInfo> {
        self.database.as_ref().map(|db| db.get_info())
    }

    pub fn is_enabled(&self) -> bool {
        self.policy.enabled && self.database.is_some()
    }

    pub fn get_policy_stats(&self) -> GeoPolicyStats {
        GeoPolicyStats {
            enabled: self.policy.enabled,
            database_loaded: self.database.is_some(),
            total_rules: self.policy.rules.len(),
            enabled_rules: self.policy.rules.iter().filter(|r| r.enabled).count(),
            default_action: self.policy.default_action.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoPolicyStats {
    pub enabled: bool,
    pub database_loaded: bool,
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub default_action: GeoAction,
}

impl Default for GeoPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: "geoip/GeoLite2-City.mmdb".to_string(),
            rules: vec![
                GeoRule {
                    name: "Block high-risk countries".to_string(),
                    condition: GeoCondition::RiskScore { min: Some(80), max: None },
                    action: GeoAction::Deny,
                    priority: 100,
                    enabled: true,
                },
                GeoRule {
                    name: "Rate limit suspicious regions".to_string(),
                    condition: GeoCondition::CountryGroup { groups: vec!["high_risk".to_string()] },
                    action: GeoAction::RateLimit { requests_per_minute: 10 },
                    priority: 90,
                    enabled: true,
                },
            ],
            default_action: GeoAction::Allow,
            update_interval_hours: 24,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy = GeoPolicy::default();
        assert!(!policy.enabled);
        assert_eq!(policy.rules.len(), 2);
        assert!(matches!(policy.default_action, GeoAction::Allow));
    }

    #[test]
    fn test_rule_evaluation() {
        let policy = GeoPolicy::default();
        let engine = GeoPolicyEngine::new(policy.clone());

        // Test with a location that would match the risk score rule
        let location = LocationInfo::new("8.8.8.8", "CN", "China");
        let result = engine.evaluate_condition(&policy.rules[0].condition, &location);
        assert!(result);
    }
}
