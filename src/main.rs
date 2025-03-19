pub mod ca;
pub mod server;

use anyhow::{Context, Result};
use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use ca::CertType;
use core::net::SocketAddr;
use rustls;
use rustls::server::WebPkiClientVerifier;
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use rustls_pki_types::{CertificateDer, pem::PemObject};

use std::sync::Arc;
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

    server::initialize(&config)?;
    let ca = ca::CertificateAuthority::new(&config)?;
    let _ = ca
        .initialize()
        .with_context(|| format!("failed to initialize ca"))?;

    // generate a test client cert as a test
    let client_name = "UO-2010933";
    let (client_cert, client_key) = ca
        .generate_certificate(ca::CertType::Agent, client_name)
        .with_context(|| format!("failed to generate client certificate"))?;
    ca::write_certificate(
        &ca.certificate_path(CertType::Agent, client_name),
        &client_cert,
    )?;
    ca::write_key(&ca.key_path(CertType::Agent, client_name), &client_key)?;

    // load CA certs into root store and set up client verifier
    let ca_cert = CertificateDer::from_pem_file(&ca.certificate_path(CertType::CA, "ca"))
        .with_context(|| format!("failed to load ca certificate from disk"))?;
    let mut roots = rustls::RootCertStore::empty();
    let _ = roots.add(ca_cert);
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots.clone()))
        .build()
        .with_context(|| format!("failed to build ca root store for client verification"))?;

    // load server certs
    let server_cert =
        CertificateDer::from_pem_file(&ca.certificate_path(CertType::Server, &config.server_name))
            .with_context(|| format!("failed to load server certificate from disk"))?;
    let server_key =
        PrivateKeyDer::from_pem_file(ca.key_path(CertType::Server, &config.server_name))
            .with_context(|| format!("failed to load server key from disk"))?;

    // Build the TLS server configuration using Rustls's builder API.
    let tls_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![server_cert.clone()], server_key)
        .expect("failed to build TLS config");
    let server_config = RustlsConfig::from_config(Arc::new(tls_config));

    let app = Router::new().route("/", get(handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 9140));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, server_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn handler() -> &'static str {
    "Hello, World!"
}
