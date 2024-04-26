use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Error as IOError, Read};
use std::result::Result;
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub oauth_auth_url: Url,
    pub oauth_device_url: Url,
    pub oauth_token_url: Url,
    pub oauth_token_introspect_url: Url,

    #[serde(default = "default_scopes")]
    pub scopes: String,

    #[serde(default = "default_true")]
    pub qr_enabled: bool,
}

pub fn read_config(path: &str) -> Result<Config, IOError> {
    let mut config_file = File::open(path)?;
    let mut buff = String::new();
    config_file.read_to_string(&mut buff)?;

    let config: Config = serde_json::from_str(&buff)?;
    Ok(config)
}

fn default_scopes() -> String {
    "openid profile".to_string()
}

fn default_true() -> bool {
    true
}
