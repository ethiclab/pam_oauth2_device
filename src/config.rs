use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::File;
use std::io::{Error as IOError, Read};
use std::result::Result;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub oauth_device_url: String,
    pub oauth_token_url: String,
    pub oauth_token_introspect_url: String,
    pub scope: Option<String>,
}

impl Config {
    pub fn get_scope(&self) -> &str {
        match &self.scope {
            Some(s) => s,
            None => "openid profile",
        }
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{\nClientId: {}\nClient Secret: {}\nOAuth Device URL: {}\nOAuth Token URL: {}\nOAuth Auth URL: {}\nScope: {}}}",
            self.client_id,
            self.client_secret,
            self.oauth_token_introspect_url,
            self.oauth_token_url,
            self.oauth_token_introspect_url,
            self.get_scope()
        )
    }
}

pub fn read_config(path: &str) -> Result<Config, IOError> {
    let mut config_file = File::open(path)?;
    let mut buff = String::new();
    config_file.read_to_string(&mut buff)?;

    let config: Config = serde_json::from_str(&buff)?;
    Ok(config)
}
