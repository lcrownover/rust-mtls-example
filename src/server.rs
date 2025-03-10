use anyhow::{Context, Result};
use std::{env, fs, path::PathBuf};

pub struct CaravelConfig {
    pub server_name: String,
    pub data_path: PathBuf,
}

impl CaravelConfig {
    pub fn new() -> Self {
        let server_name = env::var("CARAVEL_SERVER_NAME").unwrap_or(String::from("localhost"));
        let data_path: PathBuf = env::var("CARAVEL_DATA_PATH")
            .unwrap_or(String::from("/var/lib/caravel"))
            .into();

        CaravelConfig {
            server_name,
            data_path,
        }
    }
}

pub fn initialize_dirs(config: &CaravelConfig) -> Result<()> {
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
