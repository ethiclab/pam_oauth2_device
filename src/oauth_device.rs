use crate::config::Config;
use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::TimestampSeconds;
use std::collections::HashMap;
use std::fmt::Display;
use std::thread::sleep;
use std::time::Duration;
use std::time::SystemTime;

#[derive(Serialize, Deserialize, Debug)]
pub struct OAuthError {
    #[serde(rename = "error")]
    pub error_type: String,
    pub error_description: Option<String>,
}

impl std::error::Error for OAuthError {
    fn description(&self) -> &str {
        &self.error_type
    }
}

impl Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OAuth server error: {}: {}",
            self.error_type,
            self.error_description.as_deref().unwrap_or("")
        )
    }
}

#[derive(Debug)]
pub struct OAuthClient {
    pub reqwest_client: Client,
    pub reqwest_headers: HeaderMap,
    pub device_url: Url,
    pub token_url: Url,
    pub token_introspect_url: Url,
    pub client_id: String,
    pub client_secret: String,
    pub grant_type: String,
    pub scope: String,
    pub redirect_uri: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    user_code: String,
    verification_uri: String,
    pub verification_uri_complete: String,
    expires_in: usize,
    pub interval: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenResponse {
    pub access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
    expires_in: usize,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct IntrospectResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub exp: Option<SystemTime>,
}

impl OAuthClient {
    pub fn new(c: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_str("application/x-www-form-urlencoded")?,
        );
        Ok(Self {
            reqwest_client: Client::new(),
            reqwest_headers: headers,
            device_url: Url::parse(&c.oauth_device_url)?,
            token_url: Url::parse(&c.oauth_token_url)?,
            token_introspect_url: Url::parse(&c.oauth_token_introspect_url)?,
            client_id: c.client_id.clone(),
            client_secret: c.client_secret.clone(),
            grant_type: String::from("urn:ietf:params:oauth:grant-type:device_code"),
            scope: c.get_scope().to_string(),
            redirect_uri: String::from("urn:ietf:wg:oauth:2.0:oob"),
        })
    }

    pub fn device_code_req(&self) -> Result<DeviceCodeResponse, Box<dyn std::error::Error>> {
        let client = self.reqwest_client.clone();

        let mut params = HashMap::new();
        params.insert("client_id", &self.client_id);
        params.insert("client_secret", &self.client_secret);
        params.insert("scope", &self.scope);
        params.insert("redirect_uri", &self.redirect_uri);

        let req = client
            .post(self.device_url.clone())
            .headers(self.reqwest_headers.clone())
            .form(&params);

        let req = req.build()?;
        let response = client.execute(req)?;

        match response.status() {
            e if e.is_client_error() => {
                let err: OAuthError = serde_json::from_str(&response.text()?)?;
                Err(Box::new(err))
            }
            StatusCode::OK => {
                let resp: DeviceCodeResponse = serde_json::from_str(&response.text()?)?;
                Ok(resp)
            }
            _ => {
                let err: Box<dyn std::error::Error> =
                    format!("Unknown error: {:?}", &response.text()?).into();
                Err(err)
            }
        }
    }

    pub fn token_req(
        &self,
        device_code: &String,
        interval: u64,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        let client = self.reqwest_client.clone();
        let mut params = HashMap::new();
        params.insert("client_id", &self.client_id);
        params.insert("client_secret", &self.client_secret);
        params.insert("scope", &self.scope);
        params.insert("grant_type", &self.grant_type);
        params.insert("device_code", device_code);
        let req = client
            .post(self.token_url.clone())
            .headers(self.reqwest_headers.clone())
            .form(&params);

        let req = req.build()?;
        let response = client.execute(req)?;
        match response.status() {
            e if e.is_client_error() => {
                let err: OAuthError = serde_json::from_str(&response.text()?)?;
                if err.error_type == "authorization_pending" {
                    sleep(Duration::from_secs(interval));
                    self.token_req(device_code, interval)
                } else {
                    Err(Box::new(err))
                }
            }
            StatusCode::OK => {
                let resp: TokenResponse = serde_json::from_str(&response.text()?)?;
                Ok(resp)
            }
            _ => {
                let err: Box<dyn std::error::Error> =
                    format!("Unknown error: {:?}", &response.text()?).into();
                Err(err)
            }
        }
    }

    pub fn introspect_req(
        &self,
        access_token: &str,
    ) -> Result<IntrospectResponse, Box<dyn std::error::Error>> {
        let client = self.reqwest_client.clone();
        let mut params = HashMap::new();
        params.insert("token", access_token);

        let req = client
            .post(self.token_introspect_url.clone())
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&params);

        let req = req.build()?;
        let response = client.execute(req)?;

        match response.status() {
            e if e.is_client_error() => {
                let err: OAuthError = serde_json::from_str(&response.text()?)?;
                Err(Box::new(err))
            }
            StatusCode::OK => {
                let resp: IntrospectResponse = serde_json::from_str(&response.text()?)?;
                Ok(resp)
            }
            _ => {
                let err: Box<dyn std::error::Error> =
                    format!("Unknown error: {:?}", &response.text()?).into();
                Err(err)
            }
        }
    }
}

impl IntrospectResponse {
    pub fn is_active(&self) -> bool {
        if !self.active {
            log::warn!("User is inactive!");
        }
        self.active
    }
    pub fn validate_scope(&self, scope: String) -> bool {
        let valid_scope: Vec<&str> = match &self.scope {
            Some(s) => s.split_whitespace().collect(),
            None => {
                log::error!("Cannot find scope in OAuth Provider response");
                return false;
            }
        };
        let req_scope: Vec<&str> = scope.split_whitespace().collect();

        let has_scope = req_scope.iter().all(|scope| valid_scope.contains(scope));

        if !has_scope {
            log::warn!("Invalid scope!: {}", scope);
        }

        has_scope
    }
    pub fn validate_username(&self, user: &str) -> bool {
        if self.username.is_none() {
            log::error!("Cannot find username in OAuth Provider response!");
            return false;
        }
        if self.username.clone().is_some_and(|u| u != user) {
            log::warn!("Invalid username!: {}", self.username.clone().unwrap());
        }

        self.username.clone().is_some_and(|u| u == user)
    }
    pub fn validate_exp(&self) -> bool {
        if self.exp.is_none() {
            log::error!("Cannot find exp in OAuth Provider response!");
            return false;
        }
        if self.exp.is_some_and(|e| e <= SystemTime::now()) {
            log::warn!("User token expired!");
        }

        self.exp.is_some_and(|e| e > SystemTime::now())
    }
}
