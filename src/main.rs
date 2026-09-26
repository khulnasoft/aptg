use anyhow::Result;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber;

mod audit;
mod cache;
mod geoip;
mod metrics;
mod mirror;
mod policy;
mod server;
mod tls;
mod verify;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting aptg");

    let routes = server::router::build_routes();
    let addr: SocketAddr = ([0, 0, 0, 0], 8080).into();

    info!("Server listening on {}", addr);

    warp::serve(routes).run(addr).await;

    Ok(())
}
