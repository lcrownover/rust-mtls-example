use anyhow::{Context, Result};
use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use core::net::SocketAddr;
use rcgen::{Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{env, fs};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use rcgen::{BasicConstraints, DnValue::PrintableString, KeyPair, KeyUsagePurpose};
use time::OffsetDateTime;

struct ServerConfig {
    pub server_name: String,
    pub data_path: PathBuf,
}

impl ServerConfig {
    fn new() -> Self {
        let server_name = env::var("CARAVEL_SERVER_NAME").unwrap_or(String::from("localhost"));
        let data_path: PathBuf = env::var("CARAVEL_DATA_PATH")
            .unwrap_or(String::from("/var/lib/caravel"))
            .into();

        ServerConfig {
            server_name,
            data_path,
        }
    }
}

struct CertificateAuthority {
    ca_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl CertificateAuthority {
    fn initialize(config: &ServerConfig) -> Result<Self> {
        tracing::debug!("initializing ca");

        let ca_path = config.data_path.join("ca");
        if ca_path.exists() {
            fs::create_dir_all(&ca_path)
                .with_context(|| format!("Failed to initialize ca path {}", &ca_path.display()))?;
        }

        let cert_path = ca_path.join("ca.crt");
        let key_path = ca_path.join("ca.key").to_owned();

        let ca_server_path = ca_path.join("server");
        if !ca_server_path.exists() {
            fs::create_dir_all(&ca_server_path).with_context(|| {
                format!(
                    "Failed to initialize ca/server path {}",
                    &ca_server_path.display()
                )
            })?;
        }
        let ca_agents_path = ca_path.join("agents");
        if !ca_agents_path.exists() {
            fs::create_dir_all(&ca_agents_path).with_context(|| {
                format!(
                    "Failed to initialize ca/agents path {}",
                    &ca_agents_path.display()
                )
            })?;
        }

        let ca = CertificateAuthority {
            ca_path,
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        };

        if !cert_path.exists() || !key_path.exists() {
            ca.generate_ca()?
        }

        if !ca.server_cert_exists(&config.server_name) {
            let _ = ca.generate_server_certificate(&config.server_name)?;
        }

        Ok(ca)
    }

    fn server_cert_exists(&self, server_name: &str) -> bool {
        self.server_cert_path(server_name).exists() && self.server_cert_path(server_name).is_file()
    }

    fn server_cert_path(&self, server_name: &str) -> PathBuf {
        self.ca_path
            .join("server")
            .join(format!("{}.crt", server_name))
    }
    fn server_key_path(&self, server_name: &str) -> PathBuf {
        self.ca_path
            .join("server")
            .join(format!("{}.key", server_name))
    }

    pub fn key(&self) -> Result<KeyPair> {
        let ca_key = fs::read_to_string(&self.key_path).with_context(|| {
            format!(
                "Failed to read CA key from file: {}",
                &self.key_path.display()
            )
        })?;
        let keypair = KeyPair::from_pem(ca_key.as_str())
            .with_context(|| format!("Failed to parse CA key from ca.key"))?;
        Ok(keypair)
    }

    pub fn cert(&self, key: &KeyPair) -> Result<Certificate> {
        let ca_cert = fs::read_to_string(&self.cert_path)?;
        let params = CertificateParams::from_ca_cert_pem(ca_cert.as_str())
            .with_context(|| format!("Failed to parse CA cert from existing ca.crt"))?;
        let cert = params
            .self_signed(&key)
            .with_context(|| format!("Failed to sign ca cert"))?;
        Ok(cert)
    }

    fn generate_ca(&self) -> Result<()> {
        tracing::debug!("generating new ca");
        let mut params = CertificateParams::new(Vec::default())
            .expect("empty subject alt name can't produce error");
        let (today, forever) = validity_period();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            DnType::CountryName,
            PrintableString("US".try_into().unwrap()),
        );
        params
            .distinguished_name
            .push(DnType::OrganizationName, "caravel");
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);

        params.not_before = today;
        params.not_after = forever;

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = params.self_signed(&ca_key).unwrap();

        fs::write(&self.cert_path, ca_cert.pem())
            .with_context(|| format!("failed to write {}", &self.ca_path.display()))?;
        fs::write(&self.key_path, ca_key.serialize_pem())
            .with_context(|| format!("failed to write {}", &self.key_path.display()))?;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&self.key_path, permissions).with_context(|| {
            format!(
                "Failed to set permissions on ca key path {}",
                &self.key_path.display()
            )
        })?;

        Ok(())
    }

    pub fn generate_agent_certificate(&self, server_name: &str) -> Result<Certificate> {
        tracing::debug!("generating new agent cert");
        self.generate_certificate("agents".into(), server_name)
    }

    fn generate_server_certificate(&self, server_name: &str) -> Result<Certificate> {
        tracing::debug!("generating new server cert");
        self.generate_certificate("server".into(), server_name)
    }

    fn generate_certificate(&self, cert_dir: PathBuf, server_name: &str) -> Result<Certificate> {
        fs::create_dir_all(&cert_dir).with_context(|| {
            format!(
                "Failed to initialize cert directory: {}",
                &cert_dir.display()
            )
        })?;
        let mut params =
            CertificateParams::new(vec![server_name.into()]).expect("we know the name is valid");
        let (today, forever) = validity_period();
        params
            .distinguished_name
            .push(DnType::CommonName, server_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params.not_before = today;
        params.not_after = forever;

        let ca_key = &self
            .key()
            .with_context(|| format!("Failed to load CA key"))?;
        let ca_cert = &self
            .cert(ca_key)
            .with_context(|| format!("Failed to load CA cert"))?;
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca_cert, &ca_key).unwrap();

        let cert_path = cert_dir.join(format!("{}.crt", server_name));
        tracing::debug!("writing cert to {}", cert_path.display());
        fs::write(&cert_path, cert.pem())
            .with_context(|| format!("failed to write server cert: {}", &cert_dir.display()))?;
        let key_path = cert_dir.join(format!("{}.key", server_name));
        fs::write(&key_path, key.serialize_pem())
            .with_context(|| format!("failed to write server key: {}", &cert_dir.display()))?;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&key_path, permissions).with_context(|| {
            format!(
                "Failed to set permissions on server key: {}",
                &key_path.display()
            )
        })?;

        Ok(cert)
    }
}

fn initialize_dirs(config: &ServerConfig) -> Result<()> {
    tracing::debug!("initializing data path");
    if !config.data_path.exists() {
        fs::create_dir_all(&config.data_path).with_context(|| {
            format!(
                "Failed to initialize data path {}",
                &config.data_path.display()
            )
        })?;
    }

    Ok(())
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let today = OffsetDateTime::now_utc();
    let forever_year = today.date().year() + 30;
    let forever = today.replace_year(forever_year).unwrap();
    (today, forever)
}

// fn new_end_entity(ca: &Certificate, ca_key: &KeyPair) -> Certificate {
//     let name = "client_1";
//     let mut params = CertificateParams::new(vec![name.into()]).expect("we know the name is valid");
//     let (yesterday, tomorrow) = validity_period();
//     params.distinguished_name.push(DnType::CommonName, name);
//     params.use_authority_key_identifier_extension = true;
//     params.key_usages.push(KeyUsagePurpose::DigitalSignature);
//     params
//         .extended_key_usages
//         .push(ExtendedKeyUsagePurpose::ServerAuth);
//     params.not_before = yesterday;
//     params.not_after = tomorrow;
//
//     let key_pair = KeyPair::generate().unwrap();
//     params.signed_by(&key_pair, ca, ca_key).unwrap()
// }

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

    let config = ServerConfig::new();

    initialize_dirs(&config)?;
    let ca = CertificateAuthority::initialize(&config)?;

    // generate a test client cert
    let client_cert = ca.generate_agent_certificate("ODIN")?;
    println!("client cert: {}", client_cert.pem());

    let config = RustlsConfig::from_pem_file(
        ca.server_cert_path(&config.server_name),
        ca.server_key_path(&config.server_name),
    )
    .await
    .unwrap();

    let app = Router::new().route("/", get(handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 9140));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn handler() -> &'static str {
    "Hello, World!"
}
