use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub defaults: Option<DefaultsConfig>,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultsConfig {
    pub ssh_port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub name: String,
    pub host: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
}

impl ServerConfig {
    pub fn resolved_user(&self, defaults: Option<&DefaultsConfig>) -> String {
        self.user
            .clone()
            .or_else(|| defaults.and_then(|d| d.user.clone()))
            .unwrap_or_else(|| "root".to_string())
    }

    pub fn resolved_port(&self, defaults: Option<&DefaultsConfig>) -> u16 {
        self.port
            .or_else(|| defaults.and_then(|d| d.ssh_port))
            .unwrap_or(22)
    }

    pub fn resolved_identity_file(&self, defaults: Option<&DefaultsConfig>) -> Option<PathBuf> {
        let raw = self
            .identity_file
            .clone()
            .or_else(|| defaults.and_then(|d| d.identity_file.clone()));

        raw.map(|p| {
            if p.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    return home.join(p.trim_start_matches("~/"));
                }
            }
            PathBuf::from(p)
        })
    }
}

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<AppConfig> {
    let content = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read configuration file: {:?}", path.as_ref()))?;
    let config: AppConfig = toml::from_str(&content)
        .with_context(|| "Failed to parse TOML configuration file")?;
    Ok(config)
}
