use anyhow::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = PathBuf::from("config.toml");
    let config = Arc::new(tokio::sync::RwLock::new(aptg::config::AppConfig::load(
        &config_path,
    )?));
    aptg::config::AppConfig::spawn_watcher(config.clone(), config_path);

    let cfg = config.read().await;
    let addr: SocketAddr = ([0, 0, 0, 0], cfg.server.port).into();
    info!("Starting aptg on {}", addr);
    drop(cfg);

    let routes = aptg::server::router::build_routes(config).await;
    warp::serve(routes).run(addr).await;

    Ok(())
}
