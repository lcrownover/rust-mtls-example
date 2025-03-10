use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::server::CaravelConfig;

use rcgen::{BasicConstraints, DnValue::PrintableString, KeyPair, KeyUsagePurpose};
use time::OffsetDateTime;

pub struct CertificateAuthority {
    ca_path: PathBuf,
    pub cert_pem_path: PathBuf,
    pub cert_der_path: PathBuf,
    pub key_path: PathBuf,
}

impl CertificateAuthority {
    pub fn initialize(config: &CaravelConfig) -> Result<Self> {
        tracing::debug!("initializing ca");

        let ca_path = config.data_path.join("ca");
        if ca_path.exists() {
            fs::create_dir_all(&ca_path)
                .with_context(|| format!("Failed to initialize ca path {}", &ca_path.display()))?;
        }

        let cert_pem_path = ca_path.join("ca.crt");
        let cert_der_path = ca_path.join("ca.der");
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
            cert_pem_path: cert_pem_path.clone(),
            cert_der_path: cert_der_path.clone(),
            key_path: key_path.clone(),
        };

        if !cert_pem_path.exists() || !key_path.exists() {
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

    pub fn server_cert_path(&self, server_name: &str) -> PathBuf {
        self.ca_path
            .join("server")
            .join(format!("{}.crt", server_name))
    }
    pub fn server_key_path(&self, server_name: &str) -> PathBuf {
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
        let ca_cert = fs::read_to_string(&self.cert_pem_path).with_context(|| format!("Failed to read cert pem file"))?;
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

        fs::write(&self.cert_pem_path, ca_cert.pem())
            .with_context(|| format!("failed to write {}", &self.ca_path.display()))?;
        fs::write(&self.cert_der_path, ca_cert.der())
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
        self.generate_certificate(self.ca_path.join("agents").into(), server_name)
    }

    fn generate_server_certificate(&self, server_name: &str) -> Result<Certificate> {
        tracing::debug!("generating new server cert");
        self.generate_certificate(self.ca_path.join("server").into(), server_name)
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

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let today = OffsetDateTime::now_utc();
    let forever_year = today.date().year() + 30;
    let forever = today.replace_year(forever_year).unwrap();
    (today, forever)
}
