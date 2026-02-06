use anyhow::Result;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber;

mod server;
mod mirror;
mod verify;
mod policy;
mod cache;
mod audit;
mod tls;
mod geoip;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    info!("Starting aptg");
    
    let routes = server::router::build_routes();
    let addr: SocketAddr = ([0, 0, 0, 0], 8080).into();
    
    info!("Server listening on {}", addr);
    
    warp::serve(routes)
        .run(addr)
        .await;
    
    Ok(())
}
