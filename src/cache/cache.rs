use bytes::Bytes;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use warp::Reply;

pub struct CacheManager {
    cache: RwLock<HashMap<String, CacheEntry>>,
    ttl_config: TtlConfig,
    disk_cache_dir: Option<String>,
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
            release_ttl: Duration::from_secs(6 * 3600),
            packages_ttl: Duration::from_secs(12 * 3600),
            deb_ttl: Duration::from_secs(365 * 24 * 3600),
        }
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheManager {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl_config: TtlConfig::default(),
            disk_cache_dir: None,
        }
    }

    pub async fn get(&self, path: &str) -> Option<impl Reply> {
        let cache = self.cache.read().await;

        if let Some(entry) = cache.get(path) {
            if entry.created_at.elapsed() < entry.ttl {
                info!("Cache hit for: {}", path);
                return Some(self.create_warp_response(entry.data.clone()));
            } else {
                warn!("Cache expired for: {}", path);
            }
        }

        None
    }

    pub async fn store(&self, path: &str, response: impl Reply) {
        let ttl = self.determine_ttl(path);

        match self.extract_response_data(response).await {
            Ok(cached_response) => {
                let entry = CacheEntry {
                    data: cached_response.clone(),
                    created_at: Instant::now(),
                    ttl,
                };

                let mut cache = self.cache.write().await;
                cache.insert(path.to_string(), entry);
                info!("Cached response for: {} (TTL: {:?})", path, ttl);

                if let Some(ref disk_dir) = self.disk_cache_dir {
                    if let Err(e) = self
                        .store_to_disk(path, &cached_response, disk_dir.as_str())
                        .await
                    {
                        warn!("Failed to store cache to disk for {}: {}", path, e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to extract response data for {}: {}", path, e);
            }
        }
    }

    fn determine_ttl(&self, path: &str) -> Duration {
        if path.contains("InRelease") || path.contains("Release") || path.contains("Release.gpg") {
            self.ttl_config.release_ttl
        } else if path.contains("Packages") || path.contains("Sources") {
            self.ttl_config.packages_ttl
        } else if path.ends_with(".deb") {
            self.ttl_config.deb_ttl
        } else {
            Duration::from_secs(3600)
        }
    }

    async fn extract_response_data(
        &self,
        response: impl Reply,
    ) -> Result<CachedResponse, Box<dyn std::error::Error + Send + Sync>> {
        let resp = response.into_response();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = hyper::body::to_bytes(resp.into_body()).await?;
        Ok(CachedResponse {
            status,
            headers,
            body,
        })
    }

    fn create_warp_response(&self, cached: CachedResponse) -> impl Reply {
        let mut response = warp::reply::Response::new(cached.body.into());
        *response.headers_mut() = cached.headers;
        *response.status_mut() = cached.status;
        response
    }

    async fn store_to_disk(
        &self,
        path: &str,
        data: &CachedResponse,
        dir: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let safe_path = path.replace(['/', '\\'], "_");
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir)?;
        let file_path = dir.join(format!("{}.cache", safe_path));
        let mut file = fs::File::create(&file_path)?;
        use std::io::Write;
        file.write_all(&data.body)?;
        info!("Stored disk cache for: {} at {}", path, file_path.display());
        Ok(())
    }

    fn disk_cache_file_path(&self, path: &str, dir: &str) -> PathBuf {
        let safe_path = path.replace(['/', '\\'], "_");
        PathBuf::from(dir).join(format!("{}.cache", safe_path))
    }

    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("Cache cleared");

        if let Some(ref disk_dir) = self.disk_cache_dir {
            let dir = PathBuf::from(disk_dir.as_str());
            if dir.exists() {
                let _ = fs::remove_dir_all(&dir);
                info!("Disk cache directory cleared: {}", dir.display());
            }
        }
    }

    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();

        let expired_paths: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.created_at) >= entry.ttl)
            .map(|(path, _)| path.clone())
            .collect();

        for path in &expired_paths {
            if let Some(_entry) = cache.remove(path) {
                info!("Removing expired cache entry: {}", path);

                if let Some(ref disk_dir) = self.disk_cache_dir {
                    let file_path = self.disk_cache_file_path(path, disk_dir.as_str());
                    if file_path.exists() {
                        let _ = fs::remove_file(&file_path);
                        info!("Removed expired disk cache file for: {}", path);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_manager_creation() {
        let cache = CacheManager::new();
        assert!(cache.disk_cache_dir.is_none());
    }

    #[test]
    fn test_determine_ttl() {
        let cache = CacheManager::new();
        assert_eq!(
            cache.determine_ttl("/dists/stable/InRelease"),
            Duration::from_secs(6 * 3600)
        );
        assert_eq!(
            cache.determine_ttl("/dists/stable/main/binary-amd64/Packages"),
            Duration::from_secs(12 * 3600)
        );
        assert_eq!(
            cache.determine_ttl("/pool/main/pkg/pkg_1.0.deb"),
            Duration::from_secs(365 * 24 * 3600)
        );
        assert_eq!(cache.determine_ttl("/some/path"), Duration::from_secs(3600));
    }
}
