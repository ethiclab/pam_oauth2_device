use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Error as IOError, Read};
use std::result::Result;
use url::Url;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub oauth_auth_url: Url,
    pub oauth_device_url: Url,
    pub oauth_token_url: Url,
    pub oauth_token_introspect_url: Url,
    pub scope: Option<String>,

    #[serde(default = "default_qr_enabled")]
    pub qr_enabled: bool,
}

impl Config {
    pub fn get_scope(&self) -> &str {
        match &self.scope {
            Some(s) => s,
            None => "openid profile",
        }
    }
}

pub fn read_config(path: &str) -> Result<Config, IOError> {
    let mut config_file = File::open(path)?;
    let mut buff = String::new();
    config_file.read_to_string(&mut buff)?;

    let config: Config = serde_json::from_str(&buff)?;
    Ok(config)
}

fn default_qr_enabled() -> bool {
    true
}
