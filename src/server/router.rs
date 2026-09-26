use crate::audit::log::AuditLogger;
use crate::cache::cache::{CacheManager, CachedResponse};
use crate::config;
use crate::geoip::policy::{GeoPolicy, GeoPolicyEngine};
use crate::metrics::MetricsCollector;
use crate::mirror::fetch::MirrorFetcher;
use crate::policy::rules::PolicyEngine;
use crate::verify::gpg::GpgVerifier;
use std::net::SocketAddr;
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

fn with_suite(
    suite: String,
) -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || suite.clone())
}

pub async fn build_routes(
    app_config: Arc<tokio::sync::RwLock<config::AppConfig>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let config_init = app_config.read().await;
    let suite = config_init.upstream.suite.clone();
    let fetcher = Arc::new(MirrorFetcher::new(vec![config_init
        .upstream
        .base_url
        .clone()]));
    let audit = Arc::new(AuditLogger::with_log_file(&config_init.audit.log_file));
    let gpg_verifier = Arc::new(GpgVerifier::new(&config_init.verification.gpg_keyring_path));
    drop(config_init);
    let policy = Arc::new(PolicyEngine::new());
    let cache = Arc::new(CacheManager::new());
    let geo_policy = GeoPolicy::default();
    let geo_policy_engine = Arc::new(GeoPolicyEngine::new(geo_policy));
    let metrics = Arc::new(MetricsCollector::new());

    let mirror_routes = warp::path("debian")
        .and(warp::path::tail())
        .and(warp::method())
        .and(warp::header::headers_cloned())
        .and(warp::header::optional("x-forwarded-for"))
        .and(warp::addr::remote())
        .and(with_suite(suite))
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
    remote_addr: Option<SocketAddr>,
    suite: String,
    fetcher: Arc<MirrorFetcher>,
    policy: Arc<PolicyEngine>,
    cache: Arc<CacheManager>,
    audit: Arc<AuditLogger>,
    gpg_verifier: Arc<GpgVerifier>,
    geo_policy_engine: Arc<GeoPolicyEngine>,
) -> Result<Box<dyn Reply + Send>, Rejection> {
    let path = format!("/debian/{}", path_tail.as_str());

    let client_ip = extract_client_ip(&headers, &forwarded_for, remote_addr.as_ref());

    audit.log_request(&method, &path, &headers).await;

    if let Some(cached) = cache.get(&path).await {
        audit.log_cache_hit(&path).await;
        return Ok(Box::new(cached.into_reply()));
    }

    // A request with no resolvable client IP cannot be attributed, so it is
    // denied. With the socket peer fallback in extract_client_ip this now only
    // happens when the transport exposes no remote address.
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

    let response = if path.ends_with(".deb") {
        fetcher.fetch_with_hash_validation(&path, &suite).await
    } else {
        fetcher.fetch(&path).await
    };

    match response {
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

/// Resolve the client IP used for policy, rate limiting, and GeoIP lookups.
///
/// Precedence: `X-Forwarded-For` (left-most entry, as set by a trusted reverse
/// proxy) > `X-Real-IP` > `X-Forwarded` > the socket peer address.
///
/// Note that the proxy headers are only trustworthy when a trusted proxy is the
/// sole path to this service; a direct client can forge them. The socket peer
/// fallback is what makes aptg usable without a reverse proxy, but it also means
/// a direct client could spoof its identity via headers unless the deployment
/// restricts ingress.
fn extract_client_ip(
    headers: &warp::http::HeaderMap,
    forwarded_for: &Option<String>,
    remote_addr: Option<&SocketAddr>,
) -> Option<String> {
    if let Some(forwarded) = forwarded_for {
        if let Some(first) = forwarded.split(',').next().map(str::trim) {
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }

    for header in ["x-real-ip", "x-forwarded"] {
        if let Some(value) = headers.get(header) {
            if let Ok(text) = value.to_str() {
                let text = text.trim();
                if !text.is_empty() {
                    return Some(text.to_string());
                }
            }
        }
    }

    remote_addr.map(|addr| addr.ip().to_string())
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
        let peer: SocketAddr = "198.51.100.4:5555".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, &forwarded, Some(&peer)).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(
            extract_client_ip(&headers, &None, Some(&peer)).as_deref(),
            Some("10.0.0.9")
        );
    }

    #[test]
    fn client_ip_falls_back_to_socket_peer() {
        let headers = warp::http::HeaderMap::new();
        let peer: SocketAddr = "198.51.100.4:5555".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, &None, Some(&peer)).as_deref(),
            Some("198.51.100.4")
        );
    }

    #[test]
    fn client_ip_ignores_empty_proxy_headers() {
        let mut headers = warp::http::HeaderMap::new();
        headers.insert("x-real-ip", "   ".parse().unwrap());
        let peer: SocketAddr = "198.51.100.4:5555".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, &Some("  , 10.0.0.1".to_string()), Some(&peer)).as_deref(),
            Some("198.51.100.4")
        );
    }

    #[test]
    fn client_ip_is_none_only_when_nothing_resolves() {
        let headers = warp::http::HeaderMap::new();
        assert_eq!(extract_client_ip(&headers, &None, None), None);
    }

    /// End-to-end check that a request with no proxy headers is served using
    /// the socket peer address. Requires network access to the upstream mirror,
    /// so it is ignored by default: run with
    /// `cargo test -- --ignored serving_uses_socket_peer_without_proxy_headers`.
    #[tokio::test]
    #[ignore = "requires network access to the upstream mirror"]
    async fn serving_uses_socket_peer_without_proxy_headers() {
        let app_config = Arc::new(tokio::sync::RwLock::new(config::AppConfig {
            server: config::ServerConfig {
                host: "0.0.0.0".into(),
                port: 8080,
                https_port: 8443,
                enable_https: false,
            },
            tls: config::TlsConfig {
                cert_path: "c.pem".into(),
                key_path: "k.pem".into(),
                ca_path: "ca.pem".into(),
                client_auth_required: false,
                min_tls_version: "1.2".into(),
            },
            upstream: config::UpstreamConfig {
                base_url: "https://deb.debian.org".into(),
                suite: "bookworm".into(),
                timeout_seconds: 30,
                verify_ssl: true,
                ca_cert_path: "upstream-ca.pem".into(),
            },
            cache: config::CacheConfig {
                release_ttl: 21600,
                packages_ttl: 43200,
                deb_ttl: 31536000,
            },
            audit: config::AuditConfig {
                log_level: "info".into(),
                log_file: std::env::temp_dir()
                    .join("aptg-test-audit.log")
                    .to_string_lossy()
                    .into(),
            },
            verification: config::VerificationConfig {
                gpg_keyring_path: "/etc/debian-archive-keyring.gpg".into(),
                enable_gpg_verification: true,
                enable_hash_verification: true,
            },
            policy: crate::policy::rules::PolicyConfig::default(),
        }));
        let routes = build_routes(app_config).await;
        let resp = warp::test::request()
            .method("GET")
            .path("/debian/pool/main/a/apt/apt_2.6.1_amd64.deb")
            .remote_addr("198.51.100.4:5555".parse().unwrap())
            .reply(&routes)
            .await;

        assert_eq!(resp.status(), warp::http::StatusCode::OK);
        // A .deb is an ar archive and starts with the "!<arch>" magic.
        assert_eq!(&resp.body()[..8], b"!<arch>\n");
    }

    #[test]
    fn forwarded_header_is_used_when_no_forwarded_for() {
        let mut headers = warp::http::HeaderMap::new();
        headers.insert("x-forwarded", "203.0.113.22".parse().unwrap());
        let peer: SocketAddr = "198.51.100.4:5555".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, &None, Some(&peer)).as_deref(),
            Some("203.0.113.22")
        );
    }
}
