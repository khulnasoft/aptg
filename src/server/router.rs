use crate::audit::log::AuditLogger;
use crate::cache::cache::{CacheManager, CachedResponse};
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
    cache: Arc<CacheManager>,
    fetcher: Arc<MirrorFetcher>,
    gpg_verifier: Arc<GpgVerifier>,
    metrics: Arc<MetricsCollector>,
) -> Result<impl Reply, Rejection> {
    metrics.increment_total_requests().await;

    let cache_ok = cache.is_ready().await;
    let fetcher_ok = fetcher.is_ready();
    let keyring_ok = Path::new(gpg_verifier.keyring_path()).exists()
        || std::path::Path::new("/etc/debian-archive-keyring.gpg").exists();

    if cache_ok && fetcher_ok && keyring_ok {
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "status": "ready",
                "dependencies": {
                    "cache": cache_ok,
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

    if let Some(cached) = cache.get(&path).await {
        audit.log_cache_hit(&path).await;
        return Ok(Box::new(cached.into_reply()));
    }

    // Requests without a resolvable client IP cannot be attributed, so they
    // are denied rather than allowed by default. Running without a trusted
    // reverse proxy therefore requires one to set X-Forwarded-For or
    // X-Real-IP, otherwise every request is rejected with 403.
    let allowed = match &client_ip {
        Some(ip) => policy
            .check_request(ip, &path, &method)
            .await
            .unwrap_or(false),
        None => false,
    };
    if !allowed {
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

            let status = response.status;
            let body = response.body;

            // Verify signatures BEFORE caching, and fail closed: an error from
            // the verifier must not be treated as "nothing to check".
            if path.ends_with("InRelease") || path.ends_with("Release") {
                match gpg_verifier.verify_inrelease(&body) {
                    Ok(verification) if verification.valid => {
                        audit.log_verification_success(&path).await;
                    }
                    Ok(verification) => {
                        let error_msg = verification
                            .error_message
                            .as_deref()
                            .unwrap_or("Unknown error");
                        audit.log_verification_failed(&path, error_msg).await;
                        return Ok(Box::new(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error": "GPG verification failed"}),
                            ),
                            warp::http::StatusCode::BAD_GATEWAY,
                        )));
                    }
                    Err(e) => {
                        audit.log_verification_failed(&path, &e.to_string()).await;
                        return Ok(Box::new(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error": "GPG verification error"}),
                            ),
                            warp::http::StatusCode::BAD_GATEWAY,
                        )));
                    }
                }
            }

            // Only verified content is stored.
            cache
                .store(
                    &path,
                    CachedResponse {
                        status,
                        headers: response.headers,
                        body: body.clone(),
                    },
                )
                .await;

            let mut reply = warp::reply::Response::new(body.into());
            *reply.status_mut() = status;
            Ok(Box::new(reply))
        }
        Err(e) => {
            audit.log_fetch_error(&path, &e).await;
            Ok(Box::new(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                warp::http::StatusCode::BAD_GATEWAY,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn healthz_is_reachable_without_panicking() {
        let metrics = Arc::new(MetricsCollector::new());
        let reply = handle_health(metrics).await.expect("health handler");
        assert_eq!(reply.into_response().status(), warp::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint_renders_prometheus_text() {
        let metrics = Arc::new(MetricsCollector::new());
        metrics.increment_total_requests().await;
        let reply = handle_metrics(metrics).await.expect("metrics handler");
        assert_eq!(reply.into_response().status(), warp::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn converting_a_fetched_response_runs_inside_a_runtime() {
        let mut headers = warp::http::HeaderMap::new();
        headers.insert(
            warp::http::header::CONTENT_TYPE,
            warp::http::HeaderValue::from_static("application/octet-stream"),
        );

        let fetched = crate::mirror::fetch::FetchedResponse {
            status: reqwest::StatusCode::PARTIAL_CONTENT,
            headers,
            body: bytes::Bytes::from_static(b"payload"),
        };

        let response = fetched.into_http_response();
        assert_eq!(response.status(), warp::http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response
                .headers()
                .get(warp::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/octet-stream"
        );
    }

    #[test]
    fn client_ip_precedence_prefers_forwarded_for() {
        let mut headers = warp::http::HeaderMap::new();
        headers.insert("x-real-ip", "10.0.0.9".parse().unwrap());

        let forwarded = Some("203.0.113.7, 10.0.0.1".to_string());
        assert_eq!(
            extract_client_ip(&headers, &forwarded).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(
            extract_client_ip(&headers, &None).as_deref(),
            Some("10.0.0.9")
        );
    }
}
