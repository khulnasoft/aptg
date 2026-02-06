use warp::{Filter, Reply, Rejection};
use std::sync::Arc;
use crate::mirror::fetch::MirrorFetcher;
use crate::policy::rules::PolicyEngine;
use crate::cache::cache::CacheManager;
use crate::audit::log::AuditLogger;
use crate::verify::gpg::GpgVerifier;
use crate::geoip::policy::{GeoPolicyEngine, GeoPolicy};

fn with_fetcher<T: Clone + Send + Sync>(item: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_policy<T: Clone + Send + Sync>(item: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_cache<T: Clone + Send + Sync>(item: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_audit<T: Clone + Send + Sync>(item: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_gpg_verifier<T: Clone + Send + Sync>(item: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_geo_policy<T: Clone + Send + Sync>(item: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

pub fn build_routes() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let fetcher = Arc::new(MirrorFetcher::new());
    let policy = Arc::new(PolicyEngine::new());
    let cache = Arc::new(CacheManager::new());
    let audit = Arc::new(AuditLogger::new());
    let gpg_verifier = Arc::new(GpgVerifier::new("/etc/debian-archive-keyring.gpg"));
    
    let geo_policy = GeoPolicy::default();
    let geo_policy_engine = Arc::new(GeoPolicyEngine::new(geo_policy));
    
    warp::path("debian")
        .and(warp::path::tail())
        .and(warp::method())
        .and(warp::header::headers_cloned())
        .and(warp::header::optional("x-forwarded-for"))
        .and(with_fetcher(fetcher.clone()))
        .and(with_policy(policy.clone()))
        .and(with_cache(cache.clone()))
        .and(with_audit(audit.clone()))
        .and(with_gpg_verifier(gpg_verifier.clone()))
        .and(with_geo_policy(geo_policy_engine.clone()))
        .and_then(handle_debian_request)
}

async fn handle_debian_request(
    path_tail: warp::path::Tail,
    method: warp::http::Method,
    headers: warp::http::HeaderMap,
    forwarded_for: Option<String>,
    fetcher: Arc<MirrorFetcher>,
    policy: Arc<PolicyEngine>,
    cache: Arc<CacheManager>,
    audit: Arc<AuditLogger>,
    gpg_verifier: Arc<GpgVerifier>,
    geo_policy_engine: Arc<GeoPolicyEngine>,
) -> Result<Box<dyn Reply + Send>, Rejection> {
    let path = format!("/debian/{}", path_tail.as_str());
    
    let client_ip = extract_client_ip(&headers, &forwarded_for);
    
    audit.log_request(&method, &path, &headers).await;
    
    if let Some(_cached_response) = cache.get(&path).await {
        audit.log_cache_hit(&path).await;
        return Ok(Box::new(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"cached": true})),
            warp::http::StatusCode::OK,
        )));
    }
    
    if !policy.check_request(&path, &method) {
        audit.log_request(&method, &path, &headers).await;
        return Ok(Box::new(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": "Access denied by policy"})),
            warp::http::StatusCode::FORBIDDEN,
        )));
    }
    
    if let Some(ip) = &client_ip {
        if let Ok(action_result) = geo_policy_engine.check_request(ip, &path) {
            match action_result.action {
                crate::geoip::policy::GeoAction::Deny => {
                    audit.log_geoip_denied(ip, &path, "Policy denied").await;
                    return Ok(Box::new(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"error": "Access denied by GeoIP policy"})),
                        warp::http::StatusCode::FORBIDDEN,
                    )));
                }
                crate::geoip::policy::GeoAction::RateLimit { requests_per_minute: _ } => {
                    audit.log_geoip_rate_limit(ip, &path, 100).await;
                    return Ok(Box::new(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"error": "Rate limited by GeoIP policy"})),
                        warp::http::StatusCode::TOO_MANY_REQUESTS,
                    )));
                }
                crate::geoip::policy::GeoAction::Allow => {
                    audit.log_geoip_allowed(ip, &path, "Allowed").await;
                }
                crate::geoip::policy::GeoAction::LogOnly => {
                    audit.log_geoip_log_only(ip, &path, "Log only").await;
                }
                crate::geoip::policy::GeoAction::Redirect { url } => {
                    audit.log_geoip_redirect(ip, &path, &url).await;
                    return Ok(Box::new(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"redirect": url})),
                        warp::http::StatusCode::FOUND,
                    )));
                }
            }
        }
    }
    
    match fetcher.fetch(&path).await {
        Ok(response) => {
            audit.log_fetch_success(&path).await;
            cache.store(&path, &response).await;
            
            let path_str = path.as_str();
            if path_str.ends_with("InRelease") || path_str.ends_with("Release") {
                let response_bytes = extract_response_bytes(&response);
                if let Ok(verification_result) = gpg_verifier.verify_inrelease(&response_bytes) {
                    if verification_result.valid {
                        audit.log_verification_success(&path).await;
                    } else {
                        let error_msg = verification_result.error_message
                            .as_deref()
                            .unwrap_or("Unknown error");
                        audit.log_verification_failed(&path, error_msg).await;
                        return Ok(Box::new(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"error": "GPG verification failed"})),
                            warp::http::StatusCode::BAD_REQUEST,
                        )));
                    }
                }
            }
            
            Ok(Box::new(response))
        }
        Err(e) => {
            audit.log_fetch_error(&path, &e).await;
            Ok(Box::new(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            )))
        }
    }
}

fn extract_client_ip(headers: &warp::http::HeaderMap, forwarded_for: &Option<String>) -> Option<String> {
    if let Some(forwarded) = forwarded_for {
        return Some(forwarded.split(',').next().unwrap_or("").trim().to_string());
    }
    
    if let Some(real_ip) = headers.get("X-Real-IP") {
        return Some(real_ip.to_str().unwrap_or("").to_string());
    }
    
    if let Some(x_forwarded) = headers.get("X-Forwarded") {
        return Some(x_forwarded.to_str().unwrap_or("").to_string());
    }
    
    None
}

fn extract_response_bytes(_response: &impl Reply) -> Vec<u8> {
    vec![]
}
