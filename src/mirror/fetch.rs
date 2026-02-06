use anyhow::{Result, anyhow};
use reqwest::Client;
use warp::Reply;
use std::time::Duration;
use tracing::info;

pub struct MirrorFetcher {
    client: Client,
    upstream_base: String,
}

impl MirrorFetcher {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("aptg/0.1.0")
            .build()
            .expect("Failed to create HTTP client");
            
        Self {
            client,
            upstream_base: "https://deb.debian.org".to_string(),
        }
    }
    
    pub async fn fetch(&self, path: &str) -> Result<impl Reply> {
        let url = format!("{}{}", self.upstream_base, path);
        info!("Fetching from upstream: {}", url);
        
        let response = self.client.get(&url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Upstream returned status: {}", response.status()));
        }
        
        // Convert to warp response
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;
        
        let mut warp_response = warp::reply::Response::new(bytes.into());
        *warp_response.headers_mut() = headers;
        *warp_response.status_mut() = status;
        
        Ok(warp_response)
    }
}
