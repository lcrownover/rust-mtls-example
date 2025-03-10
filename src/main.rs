use crate::ca;
use crate::server;

use anyhow::Result;
use axum::{Router, routing::get};
use core::net::SocketAddr;
use rustls;
use rustls::ClientConfig;
use rustls::ServerConfig;
use rustls::server::WebPkiClientVerifier;
use rustls_platform_verifier::ConfigVerifierExt;
use std::fs::File;
use std::io::BufReader;
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

    let config = server::CaravelConfig::new();

    server::initialize_dirs(&config)?;
    let ca = ca::CertificateAuthority::initialize(&config)?;

    // generate a test client cert
    let client_cert = ca.generate_agent_certificate("ODIN")?;

    // let config = RustlsConfig::from_pem_file(
    //     ca.server_cert_path(&config.server_name),
    //     ca.server_key_path(&config.server_name),
    // )

    // let store = load_store_from_pem("certs/ca-cert.pem").unwrap();
    // let tls_config = RustlsConfig::from_config(Arc::new(
    //     ServerConfig::builder()
    //         .with_client_cert_verifier(client_cert_verifier)
    //         .with_single_cert(certs, private_key)
    //         .unwrap(),
    // ));
    let store = load_store_from_pem("/var/lib/caravel/ca/ca.crt").unwrap();
    let client_verifier = WebPkiClientVerifier::builder(store.into()).build().unwrap();
    let private_key = load_private_key_from_pem("/var/lib/caravel/server/localhost.key").unwrap();
    let certs = load_certificates_from_pem("/var/lib/caravel/server/localhost.crt").unwrap();

    // Build the TLS server configuration using Rustls's builder API.
    let tls_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, private_key)
        .expect("failed to build TLS config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let app = Router::new().route("/", get(handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 9140));
    tracing::debug!("listening on {}", addr);
    axum_server::bind(addr)
        .acceptor(acceptor.clone())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn handler() -> &'static str {
    "Hello, World!"
}

pub fn load_certificates_from_pem(path: &str) -> std::io::Result<Vec<rustls::Certificate>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).map(|c| c.unwrap().to_vec());

    Ok(certs.map(rustls::Certificate).collect())
}

pub fn load_private_key_from_pem(path: &str) -> std::io::Result<rustls::PrivateKey> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let keys = rustls_pemfile::ec_private_keys(&mut reader)
        .map(|k| k.unwrap())
        .next()
        .unwrap();

    Ok(rustls::PrivateKey(keys.secret_sec1_der().to_vec()))
}

pub fn load_store_from_pem(path: &str) -> std::io::Result<rustls::RootCertStore> {
    let ca_certs = load_certificates_from_pem(path)?;
    let mut store = rustls::RootCertStore::empty();
    for cert in &ca_certs {
        store.add(cert).unwrap();
    }

    Ok(store)
}
