use anyhow::{Context, Result, bail};
use axum::{Router, routing::get};
use rcgen::{Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{fs, net::SocketAddr};
use tokio::sync::mpsc::Sender;

use crate::server::CaravelConfig;

use rcgen::{BasicConstraints, KeyPair, KeyUsagePurpose};
use time::OffsetDateTime;

pub enum CertType {
    CA,
    Server,
    Agent,
}

impl CertType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertType::CA => "ca",
            CertType::Server => "server",
            CertType::Agent => "agent",
        }
    }
}

pub struct CaravelCA {
    pub ca_path: PathBuf,
    pub server_name: String,
}

impl CaravelCA {
    pub fn new(config: &CaravelConfig) -> Result<Self> {
        let ca_path = config.data_path.join("ca");
        if ca_path.exists() {
            fs::create_dir_all(&ca_path)
                .context(format!("Failed to initialize ca path {}", &ca_path.display()))?;
        }

        let ca_server_path = ca_path.join("server");
        if !ca_server_path.exists() {
            fs::create_dir_all(&ca_server_path).context({
                format!(
                    "Failed to initialize ca/server path {}",
                    &ca_server_path.display()
                )
            })?;
        }
        let ca_agents_path = ca_path.join("agents");
        if !ca_agents_path.exists() {
            fs::create_dir_all(&ca_agents_path).context({
                format!(
                    "Failed to initialize ca/agents path {}",
                    &ca_agents_path.display()
                )
            })?;
        }

        Ok(CaravelCA {
            ca_path,
            server_name: config.server_name.clone(),
        })
    }
    pub fn initialize(&self) -> Result<()> {
        tracing::debug!("initializing ca");

        if !self.certificate_path(&CertType::CA, "ca").exists()
            || !self.key_path(&CertType::CA, "ca").exists()
        {
            self.generate_ca(&self.server_name)?
        }

        if !self.server_cert_exists(&self.server_name) {
            let _ = self.generate_certificate(&CertType::Server, &self.server_name)?;
        }

        // test: generate a test client cert as a test
        let client_name = "UO-2010933";
        let (client_cert, client_key) = self
            .generate_certificate(&CertType::Agent, client_name)
            .context(format!("failed to generate client certificate"))?;
        self::write_certificate(
            &self.certificate_path(&CertType::Agent, client_name),
            &client_cert,
        )?;
        self::write_key(&self.key_path(&CertType::Agent, client_name), &client_key)?;
        // end test

        Ok(())
    }

    fn server_cert_exists(&self, server_name: &str) -> bool {
        self.certificate_path(&CertType::Server, server_name)
            .exists()
            && self
                .certificate_path(&CertType::Server, server_name)
                .is_file()
    }

    pub fn certificate_path(&self, cert_type: &CertType, name: &str) -> PathBuf {
        match cert_type {
            CertType::CA => self.ca_path.join("ca.crt"),
            CertType::Server => self.ca_path.join("server").join(format!("{}.crt", name)),
            CertType::Agent => self.ca_path.join("agents").join(format!("{}.crt", name)),
        }
    }
    pub fn key_path(&self, cert_type: &CertType, name: &str) -> PathBuf {
        match cert_type {
            CertType::CA => self.ca_path.join("ca.key"),
            CertType::Server => self.ca_path.join("server").join(format!("{}.key", name)),
            CertType::Agent => self.ca_path.join("agents").join(format!("{}.key", name)),
        }
    }

    pub fn key(&self, cert_type: &CertType, name: &str) -> Result<KeyPair> {
        let key_path = match cert_type {
            CertType::CA => &self.key_path(&CertType::CA, "ca"),
            CertType::Server => &self.key_path(&CertType::Server, name),
            CertType::Agent => &self.key_path(&CertType::Agent, name),
        };
        let key = fs::read_to_string(key_path).context({
            format!(
                "Failed to read {} key from file: {}",
                cert_type.as_str(),
                key_path.display()
            )
        })?;
        let keypair = KeyPair::from_pem(key.as_str())
            .context(format!("Failed to parse {} key from ca.key", cert_type.as_str()))?;
        Ok(keypair)
    }

    pub fn certificate(
        &self,
        key: &KeyPair,
        cert_type: &CertType,
        name: &str,
    ) -> Result<Certificate> {
        let cert_path = match cert_type {
            CertType::CA => &self.certificate_path(&CertType::CA, "ca"),
            CertType::Server => &self.certificate_path(&CertType::Server, name),
            CertType::Agent => &self.certificate_path(&CertType::Agent, name),
        };
        let cert = fs::read_to_string(cert_path).context({
            format!("Failed to read {} certificate pem file", cert_type.as_str())
        })?;
        let params = CertificateParams::from_ca_cert_pem(cert.as_str()).context({
            format!(
                "Failed to parse {} certificate from existing ca.crt",
                cert_type.as_str()
            )
        })?;
        let cert = params
            .self_signed(&key)
            .context(format!("Failed to sign ca cert"))?;
        Ok(cert)
    }

    fn generate_ca(&self, common_name: &str) -> Result<()> {
        let (ca_cert, ca_key) = self.generate_certificate(&CertType::CA, common_name)?;
        write_certificate(&self.certificate_path(&CertType::CA, "ca"), &ca_cert)?;
        write_key(&self.certificate_path(&CertType::CA, "ca"), &ca_key)?;
        Ok(())
    }

    pub fn generate_certificate(
        &self,
        cert_type: &CertType,
        common_name: &str,
    ) -> Result<(Certificate, KeyPair)> {
        tracing::debug!("generating new {} cert", cert_type.as_str());
        let mut params =
            CertificateParams::new(vec![common_name.into()]).expect("we know the name is valid");

        let (today, forever) = validity_period();
        params.not_before = today;
        params.not_after = forever;

        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.distinguished_name.push(DnType::CountryName, "US");
        params
            .distinguished_name
            .push(DnType::StateOrProvinceName, "Oregon");
        params
            .distinguished_name
            .push(DnType::LocalityName, "Eugene");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Caravel");

        let (cert, key) = match cert_type {
            CertType::CA => {
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.key_usages.push(KeyUsagePurpose::DigitalSignature);
                params.key_usages.push(KeyUsagePurpose::KeyCertSign);
                params.key_usages.push(KeyUsagePurpose::CrlSign);
                let ca_key = KeyPair::generate().unwrap();
                let ca_cert = params.self_signed(&ca_key).unwrap();
                (ca_cert, ca_key)
            }
            CertType::Server | CertType::Agent => {
                params.use_authority_key_identifier_extension = true;
                params.key_usages.push(KeyUsagePurpose::DigitalSignature);
                params
                    .extended_key_usages
                    .push(ExtendedKeyUsagePurpose::ServerAuth);
                params
                    .extended_key_usages
                    .push(ExtendedKeyUsagePurpose::ClientAuth);
                let ca_key = self
                    .key(&CertType::CA, "ca")
                    .context(format!("Failed to load CA key"))?;
                let ca_cert = self
                    .certificate(&ca_key, &CertType::CA, common_name)
                    .context(format!("Failed to load CA cert"))?;
                let key = KeyPair::generate()?;
                let cert = params.signed_by(&key, &ca_cert, &ca_key)?;
                (cert, key)
            }
        };

        Ok((cert, key))
    }

    pub async fn serve(&self, tx: Sender<()>) -> Result<()> {
        let app = Router::new().route("/", get(handler));

        let addr = SocketAddr::from(([127, 0, 0, 1], 9143));
        tracing::info!("Caravel CA listening on {}", addr);
        let serve_res = axum_server::bind(addr).serve(app.into_make_service()).await;
        match serve_res {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("failed to start ca: {}", e);
                let _ = tx.send(()).await;
                bail!(e);
            }
        }

        Ok(())
    }
}

async fn handler() -> &'static str {
    "hello from ca"
}

pub fn write_certificate(path: &PathBuf, cert: &Certificate) -> Result<()> {
    tracing::debug!("writing cert to {}", path.display());
    fs::write(&path, cert.pem())
        .context(format!("failed to write cert: {}", &path.display()))?;
    Ok(())
}

pub fn write_key(path: &PathBuf, key: &KeyPair) -> Result<()> {
    fs::write(&path, key.serialize_pem())
        .context(format!("failed to write key: {}", &path.display()))?;

    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&path, permissions).context({
        format!(
            "Failed to set permissions on server key: {}",
            &path.display()
        )
    })?;
    Ok(())
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let today = OffsetDateTime::now_utc();
    let forever_year = today.date().year() + 30;
    let forever = today.replace_year(forever_year).unwrap();
    (today, forever)
}
