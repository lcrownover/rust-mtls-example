use anyhow::{Context, Result, bail};
use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use rustls::{ServerConfig, server::WebPkiClientVerifier};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{env, fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::mpsc::Sender;

pub struct CaravelConfig {
    pub server_name: String,
    pub data_path: PathBuf,
}

impl CaravelConfig {
    pub fn new() -> Self {
        let server_name = env::var("CARAVEL_SERVER_NAME").unwrap_or(String::from("localhost"));
        let data_path: PathBuf = env::var("CARAVEL_DATA_PATH")
            .unwrap_or(String::from("/var/lib/caravel-rs"))
            .into();

        CaravelConfig {
            server_name,
            data_path,
        }
    }
}

pub struct CaravelServer {
    pub server_name: String,
    pub data_path: PathBuf,
    pub ca_path: PathBuf,
}

impl CaravelServer {
    pub fn new(config: &CaravelConfig, ca_path: PathBuf) -> Self {
        CaravelServer {
            server_name: config.server_name.clone(),
            data_path: config.data_path.clone(),
            ca_path,
        }
    }

    pub fn initialize(&self) -> Result<()> {
        tracing::debug!("initializing data path");
        if !self.data_path.exists() {
            fs::create_dir_all(&self.data_path).context({
                format!(
                    "Failed to initialize data path {}",
                    &self.data_path.display()
                )
            })?;
        }

        Ok(())
    }

    pub async fn serve(&self, tx: Sender<()>) -> Result<()> {
        // load CA certs into root store and set up client verifier
        let ca_cert_res = CertificateDer::from_pem_file(self.ca_cert_path()).context(format!(
            "failed to load ca certificate from disk at {}",
            self.ca_cert_path().display()
        ));
        let ca_cert = match ca_cert_res {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("failed to start server: {:#?}", e);
                let _ = tx.send(()).await;
                bail!(e);
            }
        };
        let mut roots = rustls::RootCertStore::empty();
        let _ = roots.add(ca_cert);
        let client_verifier_res = WebPkiClientVerifier::builder(Arc::new(roots.clone()))
            .build()
            .context(format!(
                "failed to build ca root store for client verification"
            ));
        let client_verifier = match client_verifier_res {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("failed to start server: {:#?}", e);
                let _ = tx.send(()).await;
                bail!(e);
            }
        };

        // load server certs
        let server_key_res = PrivateKeyDer::from_pem_file(self.server_key_path())
            .context(format!("failed to load server key from disk"));
        let server_key = match server_key_res {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("failed to start server: {:#?}", e);
                let _ = tx.send(()).await;
                bail!(e);
            }
        };
        let server_cert_res = CertificateDer::from_pem_file(self.server_cert_path())
            .context(format!("failed to load server certificate from disk"));
        let server_cert = match server_cert_res {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("failed to start server: {:#?}", e);
                let _ = tx.send(()).await;
                bail!(e);
            }
        };

        // Build the TLS server configuration using Rustls's builder API.
        let tls_config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_cert.clone()], server_key)
            .expect("failed to build TLS config");
        let server_config = RustlsConfig::from_config(Arc::new(tls_config));

        let app = Router::new().route("/", get(handler));

        let addr = SocketAddr::from(([127, 0, 0, 1], 9140));
        tracing::info!("Caravel Server listening on {}", addr);
        let serve_res = axum_server::bind_rustls(addr, server_config)
            .serve(app.into_make_service())
            .await;
        match serve_res {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("failed to start server: {:#?}", e);
                let _ = tx.send(()).await;
                bail!(e);
            }
        }

        Ok(())
    }

    fn server_cert_path(&self) -> PathBuf {
        self.ca_path
            .join("server")
            .join(format!("{}.crt", &self.server_name))
    }
    fn server_key_path(&self) -> PathBuf {
        self.ca_path
            .join("server")
            .join(format!("{}.key", &self.server_name))
    }
    fn ca_cert_path(&self) -> PathBuf {
        self.ca_path.join(format!("{}.crt", "ca"))
    }
}

async fn handler() -> &'static str {
    "Hello, server!"
}
