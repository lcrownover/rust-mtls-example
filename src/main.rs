pub mod ca;
pub mod server;

use anyhow::Result;
use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
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

    server::initialize_dirs(&config)?;
    let ca = ca::CertificateAuthority::initialize(&config)?;

    // generate a test client cert
    let _client_cert = ca.generate_agent_certificate("UO-2010933")?;

    // load CA certs into root store and set up client verifier
    let ca_cert = CertificateDer::from_pem_file(&ca.cert_pem_path)?;
    let mut roots = rustls::RootCertStore::empty();
    let _ = roots.add(ca_cert);
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots.clone())).build()?;

    // load server certs
    let server_cert = CertificateDer::from_pem_file(&ca.server_cert_path(&config.server_name))?;
    let server_key = PrivateKeyDer::from_pem_file(ca.server_key_path(&config.server_name))?;

    // Build the TLS server configuration using Rustls's builder API.
    let tls_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        // .with_no_client_auth()
        .with_single_cert(vec![server_cert.clone()], server_key)
        .expect("failed to build TLS config");
    let server_config = RustlsConfig::from_config(Arc::new(tls_config));
    let app = Router::new().route("/", get(handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 9140));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, server_config)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn handler() -> &'static str {
    "Hello, World!"
}

// pub fn load_certificates_from_pem(path: &str) -> Result<CertificateDer> {
//     // let file = File::open(path)?;
//     // let mut reader = BufReader::new(file);
//     // let certs = rustls_pemfile::certs(&mut reader).map(|c| c.unwrap().to_vec());
//     let certs: Vec<_> = CertificateDer::pem_file_iter(path).unwrap().collect();
//     let good: Vec<_> = certs.into_iter().collect();
// }
//
// pub fn load_private_key_from_pem(path: &str) -> std::io::Result<PrivatePkcs8KeyDer> {
//     let file = File::open(path)?;
//     let mut reader = BufReader::new(file);
//     let keys = rustls_pemfile::ec_private_keys(&mut reader)
//         .map(|k| k.unwrap())
//         .next()
//         .unwrap();
//
//     Ok(rustls::PrivateKey(keys.secret_sec1_der().to_vec()))
// }
//
// pub fn load_store_from_pem(path: &str) -> Result<rustls::RootCertStore> {
//     let mut store = rustls::RootCertStore::empty();
//     for cert in &ca_certs {
//         store.add(cert).unwrap();
//     }
//
//     Ok(store)
// }
