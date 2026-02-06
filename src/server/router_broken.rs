use warp::{Filter, Reply, Rejection};
use std::sync::Arc;
use crate::mirror::fetch::MirrorFetcher;
use crate::policy::rules::PolicyEngine;
use crate::cache::cache::CacheManager;
use crate::audit::log::AuditLogger;

pub fn build_routes() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let fetcher = Arc::new(MirrorFetcher::new());
    let policy = Arc::new(PolicyEngine::new());
    let cache = Arc::new(CacheManager::new());
    let audit = Arc::new(AuditLogger::new());
    
    let debian_route = warp::path("debian")
        .and(warp::path::tail())
        .and(warp::method())
        .and(warp::header::headers_cloned())
        .and(with_fetcher(fetcher.clone()))
        .and(with_policy(policy.clone()))
        .and(with_cache(cache.clone()))
        .and(with_audit(audit.clone()))
        .and_then(handle_debian_request);
    
    debian_route
}

fn with_fetcher<T: Clone + Send + Sync>(
    item: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_policy<T: Clone + Send + Sync>(
    item: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_cache<T: Clone + Send + Sync>(
    item: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_audit<T: Clone + Send + Sync>(
    item: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

async fn handle_debian_request(
    path_tail: warp::path::Tail,
    method: warp::http::Method,
    headers: warp::http::HeaderMap,
    fetcher: Arc<MirrorFetcher>,
    policy: Arc<PolicyEngine>,
    cache: Arc<CacheManager>,
    audit: Arc<AuditLogger>,
) -> Result<impl Reply, Rejection> {
    let path = format!("/debian/{}", path_tail.as_str());
    
    // Log the request
    audit.log_request(&method, &path, &headers).await;
    
    // Check policy
    if let Err(e) = policy.check_path(&path) {
        tracing::error!("Policy violation for path {}: {}", path, e);
        return Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "error": "Access denied",
                "message": e.to_string()
            })),
            warp::http::StatusCode::FORBIDDEN,
        ));
    }
    
    // Check cache first
    if let Some(cached_response) = cache.get(&path).await {
        audit.log_cache_hit(&path).await;
        return Ok(cached_response);
    }
    
    // Fetch from upstream
    match fetcher.fetch(&path).await {
        Ok(response) => {
            // Cache the response
            cache.store(&path, &response).await;
            audit.log_fetch_success(&path).await;
            Ok(response)
        }
        Err(e) => {
            tracing::error!("Failed to fetch {}: {}", path, e);
            audit.log_fetch_error(&path, &e).await;
            Ok(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "error": "Fetch failed",
                    "message": e.to_string()
                })),
                warp::http::StatusCode::BAD_GATEWAY,
            ))
        }
    }
}
