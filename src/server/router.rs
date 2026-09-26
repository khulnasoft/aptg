use crate::audit::log::AuditLogger;
use crate::cache::cache::CacheManager;
use crate::geoip::policy::{GeoPolicy, GeoPolicyEngine};
use crate::metrics::MetricsCollector;
use crate::mirror::fetch::MirrorFetcher;
use crate::policy::rules::PolicyEngine;
use crate::verify::gpg::GpgVerifier;
use std::path::Path;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

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

fn with_gpg_verifier<T: Clone + Send + Sync>(
    item: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_geo_policy<T: Clone + Send + Sync>(
    item: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

fn with_metrics<T: Clone + Send + Sync>(
    item: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || item.clone())
}

pub fn build_routes() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let fetcher = Arc::new(MirrorFetcher::new_with_default());
    let policy = Arc::new(PolicyEngine::new());
    let cache = Arc::new(CacheManager::new());
    let audit = Arc::new(AuditLogger::new());
    let gpg_verifier = Arc::new(GpgVerifier::new("/etc/debian-archive-keyring.gpg"));
    let geo_policy = GeoPolicy::default();
    let geo_policy_engine = Arc::new(GeoPolicyEngine::new(geo_policy));
    let metrics = Arc::new(MetricsCollector::new());

    let mirror_routes = warp::path("debian")
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
        .and_then(handle_debian_request);

    let health_routes = build_health_routes(
        cache.clone(),
        fetcher.clone(),
        gpg_verifier.clone(),
        metrics.clone(),
    );

    mirror_routes.or(health_routes)
}

pub fn build_health_routes(
    cache: Arc<CacheManager>,
    fetcher: Arc<MirrorFetcher>,
    gpg_verifier: Arc<GpgVerifier>,
    metrics: Arc<MetricsCollector>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let health = warp::path("healthz")
        .and(warp::get())
        .and(with_metrics(metrics.clone()))
        .and_then(handle_health);

    let ready = warp::path("readyz")
        .and(warp::get())
        .and(with_cache(cache.clone()))
        .and(with_fetcher(fetcher.clone()))
        .and(with_gpg_verifier(gpg_verifier.clone()))
        .and(with_metrics(metrics.clone()))
        .and_then(handle_ready);

    let prometheus = warp::path("metrics")
        .and(warp::get())
        .and(with_metrics(metrics.clone()))
        .and_then(handle_metrics);

    health.or(ready).or(prometheus)
}

async fn handle_health(metrics: Arc<MetricsCollector>) -> Result<impl Reply, Rejection> {
    metrics.increment_total_requests().await;
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({
            "status": "ok",
            "service": "aptg"
        })),
        warp::http::StatusCode::OK,
    ))
}

async fn handle_ready(
    _cache: Arc<CacheManager>,
    fetcher: Arc<MirrorFetcher>,
    gpg_verifier: Arc<GpgVerifier>,
    metrics: Arc<MetricsCollector>,
) -> Result<impl Reply, Rejection> {
    metrics.increment_total_requests().await;

    let cache_ok = true;
    let fetcher_ok = fetcher.is_ready();
    let keyring_ok = Path::new(gpg_verifier.keyring_path()).exists()
        || std::path::Path::new("/etc/debian-archive-keyring.gpg").exists();

    if cache_ok && fetcher_ok && keyring_ok {
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "status": "ready",
                "dependencies": {
                    "cache": true,
                    "fetcher": fetcher_ok,
                    "keyring": keyring_ok
                }
            })),
            warp::http::StatusCode::OK,
        ))
    } else {
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "status": "not_ready",
                "dependencies": {
                    "cache": cache_ok,
                    "fetcher": fetcher_ok,
                    "keyring": keyring_ok
                }
            })),
            warp::http::StatusCode::SERVICE_UNAVAILABLE,
        ))
    }
}

async fn handle_metrics(metrics: Arc<MetricsCollector>) -> Result<impl Reply, Rejection> {
    let output = metrics.prometheus_output().await;
    Ok(warp::reply::with_status(
        warp::reply::Response::new(output.into()),
        warp::http::StatusCode::OK,
    ))
}

#[allow(clippy::too_many_arguments)]
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

    let allowed = match &client_ip {
        Some(ip) => policy.check_request(ip, &path, &method).unwrap_or(false),
        None => false,
    };
    if !allowed {
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
                        warp::reply::json(
                            &serde_json::json!({"error": "Access denied by GeoIP policy"}),
                        ),
                        warp::http::StatusCode::FORBIDDEN,
                    )));
                }
                crate::geoip::policy::GeoAction::RateLimit {
                    requests_per_minute: _,
                } => {
                    audit.log_geoip_rate_limit(ip, &path, 100).await;
                    return Ok(Box::new(warp::reply::with_status(
                        warp::reply::json(
                            &serde_json::json!({"error": "Rate limited by GeoIP policy"}),
                        ),
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
            let path_str = path.as_str();
            let response_bytes = extract_response_bytes(response);
            let cached_response = warp::reply::Response::new(response_bytes.clone().into());
            cache.store(&path, cached_response).await;
            if path_str.ends_with("InRelease") || path_str.ends_with("Release") {
                if let Ok(verification_result) = gpg_verifier.verify_inrelease(&response_bytes) {
                    if verification_result.valid {
                        audit.log_verification_success(&path).await;
                    } else {
                        let error_msg = verification_result
                            .error_message
                            .as_deref()
                            .unwrap_or("Unknown error");
                        audit.log_verification_failed(&path, error_msg).await;
                        return Ok(Box::new(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error": "GPG verification failed"}),
                            ),
                            warp::http::StatusCode::BAD_REQUEST,
                        )));
                    }
                }
            }

            let mut warp_response = warp::reply::Response::new(response_bytes.into());
            *warp_response.status_mut() = warp::http::StatusCode::OK;
            Ok(Box::new(warp_response))
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

fn extract_client_ip(
    headers: &warp::http::HeaderMap,
    forwarded_for: &Option<String>,
) -> Option<String> {
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

fn extract_response_bytes(response: impl Reply) -> Vec<u8> {
    let resp = response.into_response();
    let body = resp.into_body();
    let bytes = tokio::runtime::Handle::current()
        .block_on(hyper::body::to_bytes(body))
        .unwrap_or_default();
    bytes.to_vec()
}
