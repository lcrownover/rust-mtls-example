pub mod ca;
pub mod server;

use anyhow::{Context, Result};

use server::CaravelServer;
use tokio::sync::mpsc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Set up logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = crate::server::CaravelConfig::new();

    let caravel_ca = ca::CaravelCA::new(&config)?;
    let _ = caravel_ca
        .initialize()
        .context(format!("failed to initialize ca"))?;

    let caravel_server = CaravelServer::new(&config, caravel_ca.ca_path.clone());
    caravel_server.initialize()?;

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let tx1 = shutdown_tx.clone();
    let tx2 = shutdown_tx.clone();

    tokio::spawn(async move { caravel_ca.serve(tx1).await });
    tokio::spawn(async move { caravel_server.serve(tx2).await });

    shutdown_rx.recv().await;
    tracing::info!("Shutting down");

    // let t0 = tokio::task::spawn(async move { caravel_ca.serve().await });
    // let t1 = tokio::task::spawn(async move { caravel_server.serve().await });
    // let _ = tokio::try_join!(t0, t1)?;

    Ok(())
}
