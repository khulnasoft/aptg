use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use warp::Reply;
use bytes::Bytes;
use tracing::{info, warn};

pub struct CacheManager {
    cache: RwLock<HashMap<String, CacheEntry>>,
    ttl_config: TtlConfig,
}

#[derive(Clone)]
struct CacheEntry {
    data: CachedResponse,
    created_at: Instant,
    ttl: Duration,
}

#[derive(Clone)]
pub struct CachedResponse {
    pub status: warp::http::StatusCode,
    pub headers: warp::http::HeaderMap,
    pub body: Bytes,
}

#[derive(Clone)]
pub struct TtlConfig {
    pub release_ttl: Duration,
    pub packages_ttl: Duration,
    pub deb_ttl: Duration,
}

impl Default for TtlConfig {
    fn default() -> Self {
        Self {
            release_ttl: Duration::from_secs(6 * 3600),    // 6 hours
            packages_ttl: Duration::from_secs(12 * 3600),  // 12 hours
            deb_ttl: Duration::from_secs(365 * 24 * 3600), // 1 year (effectively forever)
        }
    }
}

impl CacheManager {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl_config: TtlConfig::default(),
        }
    }
    
    pub async fn get(&self, path: &str) -> Option<impl Reply> {
        let cache = self.cache.read().await;
        
        if let Some(entry) = cache.get(path) {
            if entry.created_at.elapsed() < entry.ttl {
                info!("Cache hit for: {}", path);
                
                let _response = warp::reply::Response::new(entry.data.body.clone().into());
                
                // Copy headers and status
                let reply = CachedResponse {
                    status: entry.data.status,
                    headers: entry.data.headers.clone(),
                    body: entry.data.body.clone(),
                };
                
                return Some(self.create_warp_response(reply));
            } else {
                warn!("Cache expired for: {}", path);
            }
        }
        
        None
    }
    
    pub async fn store(&self, path: &str, response: &impl Reply) {
        let ttl = self.determine_ttl(path);
        
        // For now, we'll skip caching since we can't properly extract response data
        // In a real implementation, you'd need to properly extract the response data
        info!("Skipping cache storage for: {} (TTL: {:?})", path, ttl);
    }
    
    fn determine_ttl(&self, path: &str) -> Duration {
        if path.contains("InRelease") || path.contains("Release") || path.contains("Release.gpg") {
            self.ttl_config.release_ttl
        } else if path.contains("Packages") || path.contains("Sources") {
            self.ttl_config.packages_ttl
        } else if path.ends_with(".deb") {
            self.ttl_config.deb_ttl
        } else {
            Duration::from_secs(3600) // Default 1 hour
        }
    }
    
    async fn extract_response_data(&self, _response: &impl Reply) -> Result<CachedResponse, Box<dyn std::error::Error + Send + Sync>> {
        // This is a simplified version - in practice, you'd need to properly extract
        // the response data from the warp Reply
        // For now, we'll create a placeholder
        Ok(CachedResponse {
            status: warp::http::StatusCode::OK,
            headers: warp::http::HeaderMap::new(),
            body: Bytes::new(),
        })
    }
    
    fn create_warp_response(&self, cached: CachedResponse) -> impl Reply {
        let mut response = warp::reply::Response::new(cached.body.into());
        *response.headers_mut() = cached.headers;
        *response.status_mut() = cached.status;
        response
    }
    
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("Cache cleared");
    }
    
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        
        cache.retain(|path, entry| {
            let is_valid = now.duration_since(entry.created_at) < entry.ttl;
            if !is_valid {
                info!("Removing expired cache entry: {}", path);
            }
            is_valid
        });
    }
}
