use anyhow::{anyhow, Result};
use bytes::Bytes;
use reqwest::{header::HeaderMap, Client, Response, StatusCode};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{info, warn};
use warp::http::Response as HttpResponse;
use warp::hyper::Body;
use xz2::read::XzDecoder;

use crate::verify::hashes::HashVerifier;

const TIMEOUT_INRELEASE_RELEASE: u64 = 10;
const TIMEOUT_PACKAGES_SOURCES: u64 = 30;
const TIMEOUT_DEB: u64 = 300;
const TIMEOUT_DEFAULT: u64 = 30;

const MAX_SIZE_INRELEASE_RELEASE: u64 = 10 * 1024 * 1024;
const MAX_SIZE_PACKAGES_SOURCES: u64 = 50 * 1024 * 1024;
const MAX_SIZE_DEB: u64 = 500 * 1024 * 1024;
const MAX_SIZE_DEFAULT: u64 = 50 * 1024 * 1024;

const BASE_DELAY_MS: u64 = 100;
const MAX_RETRIES: u32 = 3;

/// An upstream response captured as plain data.
///
/// Fetching returns this instead of an opaque `Reply` so that callers can
/// inspect the body (for GPG and hash verification) and persist the exact
/// status and headers without having to re-read an already-consumed body.
pub struct FetchedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl FetchedResponse {
    pub fn into_http_response(self) -> HttpResponse<Body> {
        let mut response = HttpResponse::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

/// Cached parsed contents of a Packages file.
///
/// Refreshed automatically when the entry ages past `ttl`.
struct PackagesCacheEntry {
    hashes: HashMap<String, String>,
    fetched_at: SystemTime,
}

pub struct PackagesCache {
    entries: Arc<RwLock<HashMap<String, PackagesCacheEntry>>>,
    ttl: Duration,
}

impl PackagesCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    pub async fn get(&self, key: &str) -> Option<HashMap<String, String>> {
        let entries = self.entries.read().await;
        entries.get(key).and_then(|e| {
            if e.fetched_at.elapsed().unwrap_or(Duration::ZERO) < self.ttl {
                Some(e.hashes.clone())
            } else {
                None
            }
        })
    }

    pub async fn insert(&self, key: String, hashes: HashMap<String, String>) {
        let mut entries = self.entries.write().await;
        entries.insert(
            key,
            PackagesCacheEntry {
                hashes,
                fetched_at: SystemTime::now(),
            },
        );
    }
}

pub struct MirrorFetcher {
    client: Client,
    upstream_urls: Vec<String>,
    current_index: usize,
    packages_cache: Arc<PackagesCache>,
}

impl MirrorFetcher {
    pub fn new(upstream_urls: Vec<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_DEFAULT))
            .user_agent("aptg/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        let urls = if upstream_urls.is_empty() {
            vec!["https://deb.debian.org".to_string()]
        } else {
            upstream_urls
        };

        Self {
            client,
            upstream_urls: urls,
            current_index: 0,
            packages_cache: Arc::new(PackagesCache::new(Duration::from_secs(3600))),
        }
    }

    pub fn new_with_default() -> Self {
        Self::new(vec!["https://deb.debian.org".to_string()])
    }

    pub fn is_ready(&self) -> bool {
        !self.upstream_urls.is_empty()
    }

    pub fn keyring_path(&self) -> String {
        "/etc/debian-archive-keyring.gpg".to_string()
    }

    fn get_timeout_for_path(&self, path: &str) -> u64 {
        if path.contains("InRelease") || path.ends_with("Release") {
            TIMEOUT_INRELEASE_RELEASE
        } else if path.contains("Packages") || path.contains("Sources") {
            TIMEOUT_PACKAGES_SOURCES
        } else if path.ends_with(".deb") {
            TIMEOUT_DEB
        } else {
            TIMEOUT_DEFAULT
        }
    }

    fn get_max_size_for_path(&self, path: &str) -> u64 {
        if path.contains("InRelease") || path.ends_with("Release") {
            MAX_SIZE_INRELEASE_RELEASE
        } else if path.contains("Packages") || path.contains("Sources") {
            MAX_SIZE_PACKAGES_SOURCES
        } else if path.ends_with(".deb") {
            MAX_SIZE_DEB
        } else {
            MAX_SIZE_DEFAULT
        }
    }

    fn get_file_name(&self, path: &str) -> String {
        path.split('/').next_back().unwrap_or("").to_string()
    }

    pub async fn health_check(&self) -> Result<bool> {
        for url in &self.upstream_urls {
            let health_url = format!("{}{}", url, "/");
            info!("Health check for upstream: {}", health_url);
            match self.client.get(&health_url).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        info!("Upstream {} is healthy", url);
                        return Ok(true);
                    }
                }
                Err(e) => {
                    warn!("Health check failed for {}: {}", url, e);
                }
            }
        }
        warn!("No healthy upstream found");
        Ok(false)
    }

    async fn fetch_with_retries(&self, url: &str, path: &str) -> Result<Response> {
        let mut delay = Duration::from_millis(BASE_DELAY_MS);
        let multiplier = 2.0;
        let max_interval = Duration::from_secs(5);

        for attempt in 0..MAX_RETRIES {
            match self.client.get(format!("{}{}", url, path)).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        return Ok(resp);
                    }
                    return Err(anyhow!("Upstream returned status: {}", resp.status()));
                }
                Err(e) => {
                    warn!(
                        "Retry attempt {}/{} failed for {}: {}",
                        attempt + 1,
                        MAX_RETRIES,
                        url,
                        e
                    );
                    let jitter_ms = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or(Duration::from_millis(0))
                        .subsec_millis() as u64
                        % delay.as_millis() as u64;
                    let jitter = Duration::from_millis(jitter_ms);
                    tokio::time::sleep(delay + jitter).await;
                    delay = Duration::from_millis((delay.as_millis() as f64 * multiplier) as u64);
                    if delay > max_interval {
                        delay = max_interval;
                    }
                }
            }
        }
        Err(anyhow!("All retries exhausted for {}", url))
    }

    fn validate_content_length(&self, response: &Response, path: &str) -> Result<()> {
        let max_size = self.get_max_size_for_path(path);
        if let Some(content_length) = response.content_length() {
            if content_length > max_size {
                return Err(anyhow!(
                    "Content-Length {} exceeds max size {} for {}",
                    content_length,
                    max_size,
                    path
                ));
            }
        }
        Ok(())
    }

    fn validate_body_size(&self, bytes: &[u8], path: &str) -> Result<()> {
        let max_size = self.get_max_size_for_path(path);
        if bytes.len() as u64 > max_size {
            return Err(anyhow!(
                "Response body size {} exceeds max size {} for {}",
                bytes.len(),
                max_size,
                path
            ));
        }
        Ok(())
    }

    pub async fn fetch(&self, path: &str) -> Result<FetchedResponse> {
        let _timeout = self.get_timeout_for_path(path);
        let _max_size = self.get_max_size_for_path(path);

        let file_name = self.get_file_name(path);
        let mut last_error = None;

        for url in &self.upstream_urls {
            info!("Fetching from upstream: {}{}", url, path);

            let response = match self.fetch_with_retries(url, path).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("Failed to fetch from {}: {}", url, e);
                    last_error = Some(e);
                    continue;
                }
            };

            if let Err(e) = self.validate_content_length(&response, path) {
                warn!("Content length validation failed for {}: {}", url, e);
                last_error = Some(e);
                continue;
            }

            let status = response.status();
            let headers = response.headers().clone();
            let bytes = match response.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to read response body from {}: {}", url, e);
                    last_error = Some(anyhow!("Failed to read body: {}", e));
                    continue;
                }
            };

            if let Err(e) = self.validate_body_size(&bytes, path) {
                warn!("Body size validation failed for {}: {}", url, e);
                last_error = Some(e);
                continue;
            }

            let fetched = FetchedResponse {
                status,
                headers,
                body: bytes,
            };

            info!("Successfully fetched {}{} from {}", file_name, path, url);
            return Ok(fetched);
        }

        Err(last_error.unwrap_or_else(|| anyhow!("All upstreams failed for {}", path)))
    }

    pub async fn fetch_with_etag(&self, path: &str, etag: &str) -> Result<FetchedResponse> {
        info!("Fetching with ETag for path: {}, etag: {}", path, etag);

        let _timeout = self.get_timeout_for_path(path);
        let _max_size = self.get_max_size_for_path(path);

        let mut last_error = None;

        for url in &self.upstream_urls {
            info!("Fetching with ETag from upstream: {}{}", url, path);

            let response = match self.fetch_with_retries(url, path).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("Failed to fetch from {}: {}", url, e);
                    last_error = Some(e);
                    continue;
                }
            };

            if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                info!(
                    "Resource not modified (304) for {}, returning cached response",
                    path
                );
                return Ok(FetchedResponse {
                    status: reqwest::StatusCode::NOT_MODIFIED,
                    headers: HeaderMap::new(),
                    body: Bytes::new(),
                });
            }

            if !response.status().is_success() {
                last_error = Some(anyhow!("Upstream returned status: {}", response.status()));
                continue;
            }

            if let Err(e) = self.validate_content_length(&response, path) {
                warn!("Content length validation failed: {}", e);
                last_error = Some(e);
                continue;
            }

            let status = response.status();
            let headers = response.headers().clone();
            let bytes = match response.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to read response body: {}", e);
                    last_error = Some(anyhow!("Failed to read body: {}", e));
                    continue;
                }
            };

            if let Err(e) = self.validate_body_size(&bytes, path) {
                warn!("Body size validation failed: {}", e);
                last_error = Some(e);
                continue;
            }

            return Ok(FetchedResponse {
                status,
                headers,
                body: bytes,
            });
        }

        Err(last_error.unwrap_or_else(|| anyhow!("All upstreams failed for {}", path)))
    }

    pub async fn fetch_with_hash_validation(
        &self,
        path: &str,
        suite: &str,
    ) -> Result<FetchedResponse> {
        let file_name = self.get_file_name(path);
        let component = self.extract_component(path);
        let arch = self.extract_arch(&file_name);
        let packages_path = format!("/debian/dists/{suite}/{component}/binary-{arch}/Packages.xz");

        info!(
            "Fetching with hash validation for path: {}, file_name: {}",
            path, file_name
        );

        let cache_key = format!("{suite}/{component}/binary-{arch}/Packages");
        let hashes = match self.packages_cache.get(&cache_key).await {
            Some(h) => {
                info!("Using cached Packages hashes for {}", cache_key);
                h
            }
            None => {
                let packages_compressed = match self.fetch_release(&packages_path).await {
                    Ok(b) => b,
                    Err(e) => {
                        return Err(anyhow!(
                            "Failed to fetch Packages file for hash validation: {}",
                            e
                        ));
                    }
                };
                let packages_content =
                    String::from_utf8(Self::decompress_xz(&packages_compressed)?)
                        .map_err(|e| anyhow!("Packages file is not valid UTF-8: {}", e))?;
                let hashes = self.find_all_hashes_in_packages(&packages_content);
                self.packages_cache.insert(cache_key, hashes.clone()).await;
                hashes
            }
        };

        let expected_hash = hashes
            .get(file_name.as_str())
            .ok_or_else(|| anyhow!("No hash found for {} in Packages", file_name))?;

        let _timeout = self.get_timeout_for_path(path);
        let _max_size = self.get_max_size_for_path(path);

        let mut last_error = None;

        for url in &self.upstream_urls {
            info!(
                "Fetching with hash validation from upstream: {}{}",
                url, path
            );

            let response = match self.fetch_with_retries(url, path).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("Failed to fetch from {}: {}", url, e);
                    last_error = Some(e);
                    continue;
                }
            };

            if let Err(e) = self.validate_content_length(&response, path) {
                warn!("Content length validation failed: {}", e);
                last_error = Some(e);
                continue;
            }

            let status = response.status();
            let headers = response.headers().clone();
            let bytes = match response.bytes().await {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    warn!("Failed to read response body: {}", e);
                    last_error = Some(anyhow!("Failed to read body: {}", e));
                    continue;
                }
            };

            if let Err(e) = self.validate_body_size(&bytes, path) {
                warn!("Body size validation failed: {}", e);
                last_error = Some(e);
                continue;
            }

            if let Err(e) = HashVerifier::verify_package_hash(&bytes, expected_hash) {
                warn!("Hash validation failed for {}: {}", file_name, e);
                last_error = Some(e);
                continue;
            }

            info!("Hash validation successful for {} from {}", file_name, url);

            return Ok(FetchedResponse {
                status,
                headers,
                body: bytes.into(),
            });
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!(
                "All upstreams failed or hash validation failed for {}",
                path
            )
        }))
    }

    fn extract_component(&self, path: &str) -> String {
        let after_pool = path.strip_prefix("/debian/pool/").unwrap_or(path);
        after_pool.split('/').next().unwrap_or("main").to_string()
    }

    fn extract_arch(&self, file_name: &str) -> String {
        if let Some(idx) = file_name.rfind('_') {
            let after = &file_name[idx + 1..];
            if let Some(dot) = after.find('.') {
                let arch = &after[..dot];
                if arch.ends_with("amd64") || arch.ends_with("arm64") || arch.ends_with("all") {
                    return arch.to_string();
                }
            }
        }
        "amd64".to_string()
    }

    fn find_all_hashes_in_packages(&self, content: &str) -> HashMap<String, String> {
        let mut hashes = HashMap::new();
        let mut current_filename: Option<String> = None;
        let mut current_hash: Option<String> = None;

        for line in content.lines() {
            if line.is_empty() {
                if let (Some(fn_), Some(h)) = (&current_filename, &current_hash) {
                    hashes.insert(fn_.clone(), h.clone());
                }
                current_filename = None;
                current_hash = None;
                continue;
            }

            if let Some(val) = line.strip_prefix("Filename: ") {
                let basename = val.trim().rsplit('/').next().unwrap_or("").to_string();
                current_filename = Some(basename);
            } else if let Some(val) = line.strip_prefix("SHA256: ") {
                current_hash = Some(val.trim().to_string());
            }
        }
        if let (Some(fn_), Some(h)) = (&current_filename, &current_hash) {
            hashes.insert(fn_.clone(), h.clone());
        }
        hashes
    }

    async fn fetch_release(&self, release_path: &str) -> Result<Vec<u8>> {
        let mut last_error = None;

        for url in &self.upstream_urls {
            let response = match self.fetch_with_retries(url, release_path).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("Failed to fetch Release from {}: {}", url, e);
                    last_error = Some(e);
                    continue;
                }
            };

            let bytes = match response.bytes().await {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    warn!("Failed to read Release body from {}: {}", url, e);
                    last_error = Some(anyhow!("Failed to read Release body: {}", e));
                    continue;
                }
            };

            if let Err(e) = self.validate_body_size(&bytes, release_path) {
                warn!("Release body size validation failed: {}", e);
                last_error = Some(e);
                continue;
            }

            return Ok(bytes);
        }

        Err(last_error.unwrap_or_else(|| anyhow!("Failed to fetch Release file")))
    }

    fn decompress_xz(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = XzDecoder::new(data);
        let mut decompressed = Vec::with_capacity(data.len() * 10);
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    pub fn set_current_upstream(&mut self, index: usize) {
        if index < self.upstream_urls.len() {
            self.current_index = index;
        }
    }

    pub fn next_upstream(&mut self) -> &str {
        self.current_index = (self.current_index + 1) % self.upstream_urls.len();
        &self.upstream_urls[self.current_index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_for_path() {
        let fetcher = MirrorFetcher::new_with_default();
        assert_eq!(fetcher.get_timeout_for_path("/dists/stable/InRelease"), 10);
        assert_eq!(fetcher.get_timeout_for_path("/dists/stable/Release"), 10);
        assert_eq!(
            fetcher.get_timeout_for_path("/dists/stable/main/binary-amd64/Packages"),
            30
        );
        assert_eq!(
            fetcher.get_timeout_for_path("/dists/stable/main/binary-amd64/Sources"),
            30
        );
        assert_eq!(
            fetcher.get_timeout_for_path("/pool/main/pkg/pkg_1.0.deb"),
            300
        );
        assert_eq!(fetcher.get_timeout_for_path("/some/other/path"), 30);
    }

    #[test]
    fn test_max_size_for_path() {
        let fetcher = MirrorFetcher::new_with_default();
        assert_eq!(
            fetcher.get_max_size_for_path("/dists/stable/InRelease"),
            10 * 1024 * 1024
        );
        assert_eq!(
            fetcher.get_max_size_for_path("/dists/stable/Release"),
            10 * 1024 * 1024
        );
        assert_eq!(
            fetcher.get_max_size_for_path("/dists/stable/main/binary-amd64/Packages"),
            50 * 1024 * 1024
        );
        assert_eq!(
            fetcher.get_max_size_for_path("/pool/main/pkg/pkg_1.0.deb"),
            500 * 1024 * 1024
        );
        assert_eq!(
            fetcher.get_max_size_for_path("/some/other/path"),
            50 * 1024 * 1024
        );
    }
}
