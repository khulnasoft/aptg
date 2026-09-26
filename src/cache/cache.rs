use bytes::Bytes;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

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

impl CachedResponse {
    /// Rebuild a reply that preserves the original upstream status and headers.
    pub fn into_reply(self) -> warp::reply::Response {
        let mut response = warp::reply::Response::new(self.body.into());
        *response.headers_mut() = self.headers;
        *response.status_mut() = self.status;
        response
    }
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
        Self::new_with_disk_cache("")
    }

    /// Create a cache that also persists bodies under `dir`.
    ///
    /// An empty `dir` disables disk caching.
    pub fn new_with_disk_cache(dir: &str) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl_config: TtlConfig::default(),
            disk_cache_dir: if dir.is_empty() {
                None
            } else {
                Some(dir.to_string())
            },
        }
    }

    pub async fn get(&self, path: &str) -> Option<CachedResponse> {
        let cache = self.cache.read().await;

        if let Some(entry) = cache.get(path) {
            if entry.created_at.elapsed() < entry.ttl {
                info!("Cache hit for: {}", path);
                return Some(entry.data.clone());
            } else {
                warn!("Cache expired for: {}", path);
            }
        }

        None
    }

    pub async fn store(&self, path: &str, data: CachedResponse) {
        let ttl = self.determine_ttl(path);

        let entry = CacheEntry {
            data: data.clone(),
            created_at: Instant::now(),
            ttl,
        };

        let mut cache = self.cache.write().await;
        cache.insert(path.to_string(), entry);
        info!("Cached response for: {} (TTL: {:?})", path, ttl);

        if let Some(ref disk_dir) = self.disk_cache_dir {
            if let Err(e) = self.store_to_disk(path, &data, disk_dir.as_str()).await {
                warn!("Failed to store cache to disk for {}: {}", path, e);
            }
        }
    }

    /// Report whether the cache is usable.
    ///
    /// Verifies the in-memory store can be locked and, when a disk cache
    /// directory is configured, that the directory is present and writable.
    pub async fn is_ready(&self) -> bool {
        // Acquire and release the read lock to confirm the store is usable.
        {
            let _guard = self.cache.read().await;
        }

        match &self.disk_cache_dir {
            Some(dir) => {
                let path = PathBuf::from(dir);
                if !path.is_dir() {
                    return false;
                }
                let probe = path.join(".aptg-readiness-probe");
                match fs::File::create(&probe) {
                    Ok(_) => {
                        let _ = fs::remove_file(&probe);
                        true
                    }
                    Err(e) => {
                        warn!("Cache disk directory not writable: {}", e);
                        false
                    }
                }
            }
            None => true,
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

    fn sample() -> CachedResponse {
        let mut headers = warp::http::HeaderMap::new();
        headers.insert(
            warp::http::header::CONTENT_TYPE,
            warp::http::HeaderValue::from_static("application/octet-stream"),
        );
        CachedResponse {
            status: warp::http::StatusCode::PARTIAL_CONTENT,
            headers,
            body: Bytes::from_static(b"package-bytes"),
        }
    }

    const PATH: &str = "/debian/dists/stable/InRelease";

    #[tokio::test]
    async fn cache_round_trip_preserves_status_headers_and_body() {
        let cache = CacheManager::new();
        cache.store(PATH, sample()).await;

        let cached = cache.get(PATH).await.expect("expected cache hit");
        assert_eq!(cached.status, warp::http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            cached
                .headers
                .get(warp::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/octet-stream"
        );
        assert_eq!(&cached.body[..], b"package-bytes");
    }

    #[tokio::test]
    async fn cache_miss_for_unknown_path() {
        let cache = CacheManager::new();
        assert!(cache.get("/debian/never-stored.deb").await.is_none());
    }

    #[tokio::test]
    async fn into_reply_keeps_original_status() {
        let reply = sample().into_reply();
        assert_eq!(reply.status(), warp::http::StatusCode::PARTIAL_CONTENT);
    }

    #[tokio::test]
    async fn clear_and_cleanup_remove_entries() {
        let cache = CacheManager::new();
        cache.store("/debian/a.deb", sample()).await;
        assert!(cache.get("/debian/a.deb").await.is_some());

        cache.clear().await;
        assert!(cache.get("/debian/a.deb").await.is_none());

        cache.store("/debian/b.deb", sample()).await;
        cache.cleanup_expired().await;
        assert!(cache.get("/debian/b.deb").await.is_some());
    }

    #[tokio::test]
    async fn is_ready_without_disk_cache() {
        let cache = CacheManager::new();
        assert!(cache.is_ready().await);
    }

    #[tokio::test]
    async fn is_ready_reports_unwritable_disk_dir() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("does-not-exist");
        let cache = CacheManager::new_with_disk_cache(missing.to_str().unwrap());
        assert!(!cache.is_ready().await);
    }

    #[tokio::test]
    async fn is_ready_with_writable_disk_dir() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cache = CacheManager::new_with_disk_cache(dir.path().to_str().unwrap());
        assert!(cache.is_ready().await);
    }
}
