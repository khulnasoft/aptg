use anyhow::{anyhow, Result};
use reqwest::{Client, Response};
use std::time::{Duration, SystemTime};
use tracing::{info, warn};
use warp::Reply;

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

pub struct MirrorFetcher {
    client: Client,
    upstream_urls: Vec<String>,
    current_index: usize,
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
        path.split('/').last().unwrap_or("").to_string()
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
            match self.client.get(&format!("{}{}", url, path)).send().await {
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
            if content_length > max_size as u64 {
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

    pub async fn fetch(&self, path: &str) -> Result<impl Reply> {
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

            let mut warp_response = warp::reply::Response::new(bytes.into());
            *warp_response.headers_mut() = headers;
            *warp_response.status_mut() = status;

            info!("Successfully fetched {}{} from {}", file_name, path, url);
            return Ok(warp_response);
        }

        Err(last_error.unwrap_or_else(|| anyhow!("All upstreams failed for {}", path)))
    }

    pub async fn fetch_with_etag(&self, path: &str, etag: &str) -> Result<impl Reply> {
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
                let mut warp_response =
                    warp::reply::Response::new(warp::hyper::Body::empty().into());
                *warp_response.status_mut() = reqwest::StatusCode::NOT_MODIFIED;
                return Ok(warp_response);
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

            let mut warp_response = warp::reply::Response::new(bytes.into());
            *warp_response.headers_mut() = headers;
            *warp_response.status_mut() = status;

            return Ok(warp_response);
        }

        Err(last_error.unwrap_or_else(|| anyhow!("All upstreams failed for {}", path)))
    }

    pub async fn fetch_with_hash_validation(&self, path: &str) -> Result<impl Reply> {
        let file_name = self.get_file_name(path);
        let release_path = path.replace(file_name.as_str(), "Release");

        info!(
            "Fetching with hash validation for path: {}, file_name: {}",
            path, file_name
        );

        let release_bytes = match self.fetch_release(release_path.as_str()).await {
            Ok(b) => b,
            Err(e) => {
                return Err(anyhow!(
                    "Failed to fetch Release file for hash validation: {}",
                    e
                ));
            }
        };

        let release_content = String::from_utf8(release_bytes.clone())
            .map_err(|e| anyhow!("Release file is not valid UTF-8: {}", e))?;

        let release_hashes = HashVerifier::parse_release_hashes(&release_content)?;

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

            if let Err(e) =
                HashVerifier::verify_file_against_release(&bytes, &file_name, &release_hashes)
            {
                warn!("Hash validation failed for {}: {}", file_name, e);
                last_error = Some(e);
                continue;
            }

            info!("Hash validation successful for {} from {}", file_name, url);

            let mut warp_response = warp::reply::Response::new(bytes.into());
            *warp_response.headers_mut() = headers;
            *warp_response.status_mut() = status;

            return Ok(warp_response);
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!(
                "All upstreams failed or hash validation failed for {}",
                path
            )
        }))
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
