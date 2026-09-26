use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

fn usage() -> ! {
    eprintln!("Usage: aptg --config <path>");
    std::process::exit(2);
}

fn parse_args() -> Result<PathBuf> {
    let mut args = std::env::args().peekable();
    args.next(); // binary name
    let mut config_path = PathBuf::from("config.toml");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config_path = args
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| anyhow!("--config requires a path"))?;
            }
            _ => usage(),
        }
    }
    Ok(config_path)
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = parse_args()?;
    let config = Arc::new(tokio::sync::RwLock::new(aptg::config::AppConfig::load(
        &config_path,
    )?));

    let policy_config = config.read().await.policy.clone();
    let policy_engine = Arc::new(tokio::sync::RwLock::new(
        aptg::policy::rules::PolicyEngine::from_config_with_banlist(
            policy_config,
            PathBuf::from("banlist.json"),
        ),
    ));

    aptg::config::AppConfig::spawn_watcher(
        config.clone(),
        config_path.clone(),
        policy_engine.clone(),
    );

    let cfg = config.read().await;
    let addr: SocketAddr = ([0, 0, 0, 0], cfg.server.port).into();
    info!(
        "Starting aptg on {} (config: {})",
        addr,
        config_path.display()
    );
    drop(cfg);

    let routes = aptg::server::router::build_routes(config, policy_engine).await;
    warp::serve(routes).run(addr).await;

    Ok(())
}
