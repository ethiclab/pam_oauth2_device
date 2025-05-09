use std::time::Duration;

use crate::config::Config;
use oauth2::basic::BasicClient;
use oauth2::curl::http_client;
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::{AccessToken, AuthUrl, ClientId, ClientSecret, DeviceAuthorizationUrl, RedirectUrl, Scope, TokenUrl};

use serde::Deserialize;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use reqwest::blocking::{get, Client};
use anyhow::Result;
use base64;
use base64::Engine;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(()),
    Multiple(()),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    email: Option<String>,
    preferred_username: Option<String>,
    aud: Option<Audience>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Jwk {
    n: String,
    e: String,
    #[serde(default)]
    kty: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug)]
pub struct OAuthClient {
    client: BasicClient,
    scopes: Vec<Scope>,
    config: Config,
}

impl OAuthClient {
    pub fn new(c: &Config) -> Result<Self> {
        let client_id = ClientId::new(c.client_id.clone());
        let client_secret = ClientSecret::new(c.client_secret.clone());
        let auth_url = AuthUrl::from_url(c.oauth_auth_url.clone());
        let token_url = TokenUrl::from_url(c.oauth_token_url.clone());
        let device_url = DeviceAuthorizationUrl::from_url(c.oauth_device_url.clone());
        let redirect_url = RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string())?;
        let scopes = c
            .scopes
            .split_whitespace()
            .map(|s| Scope::new(s.to_string()))
            .collect();

        let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_device_authorization_url(device_url)
            .set_redirect_uri(redirect_url);

        Ok(Self { client, scopes, config: c.clone() })
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    pub fn device_code(&self) -> Result<StandardDeviceAuthorizationResponse, Box<dyn std::error::Error>> {
        let details: StandardDeviceAuthorizationResponse = self
            .client
            .exchange_device_code()?
            .add_scopes(self.scopes.clone())
            .request(http_client)?;
        Ok(details)
    }

    pub fn get_token(
        &self,
        details: &StandardDeviceAuthorizationResponse,
        timeout: Option<Duration>,
    ) -> Result<AccessToken, Box<dyn std::error::Error>> {
        let client = Client::new();
        let device_code = details.device_code().secret();
        let tenant_fallback = "common".to_string();
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id.as_ref().unwrap_or(&tenant_fallback)
        );

        let start = std::time::Instant::now();
        let poll_interval = details.interval();
        let max_duration = timeout.unwrap_or_else(|| Duration::from_secs(600));

        while start.elapsed() < max_duration {
            let mut params = HashMap::new();
            params.insert("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
            params.insert("client_id", &self.config.client_id);
            params.insert("device_code", device_code);
            params.insert("client_secret", &self.config.client_secret);

            let resp = client.post(&url).form(&params).send()?;
            let status = resp.status();
            let body: Value = resp.json()?;

            if status == 200 {
                if let Some(id_token) = body.get("id_token") {
                    let token = id_token.as_str().ok_or("id_token not a string")?;
                    return Ok(AccessToken::new(token.to_string()));
                } else {
                    return Err(anyhow::anyhow!("Token response missing id_token").into());
                }
            } else if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
                if err == "authorization_pending" {
                    std::thread::sleep(poll_interval);
                    continue;
                } else {
                    return Err(anyhow::anyhow!("OAuth error: {}", err).into());
                }
            } else {
                return Err(anyhow::anyhow!("Unexpected token response: {:?}", body).into());
            }
        }

        return Err(anyhow::anyhow!("Timeout while polling for token").into());

    }

    pub fn validate_token_claims(
        &self,
        token: &AccessToken,
        remote_username: &str,
        local_user: &str,
    ) -> bool {
        if !valid_user(remote_username, local_user) {
            return false;
        }

        let header = match jsonwebtoken::decode_header(token.secret()) {
            Ok(h) => h,
            Err(e) => {
                log::error!("Failed to decode token header: {}", e);
                return false;
            }
        };

        let kid = match header.kid {
            Some(k) => k,
            None => {
                log::error!("No kid in token header");
                return false;
            }
        };

        let tenant_fallback = "common".to_string();
        let jwks_url = format!(
            "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
            self.config.tenant_id.as_ref().unwrap_or(&tenant_fallback)
        );
        let jwks: Jwks = match get(&jwks_url).and_then(|r| r.json()) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to fetch JWKS: {}", e);
                return false;
            }
        };

        let jwk = match jwks.keys.into_iter().find(|j| j.kid.as_deref() == Some(&kid)) {
            Some(j) => j,
            None => {
                log::error!("No matching key for kid {}", kid);
                return false;
            }
        };

        let decoding_key = match DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to create decoding key: {}", e);
                return false;
            }
        };

        let mut validation = Validation::new(Algorithm::RS256);
        let tenant_id = self.config.tenant_id.as_deref().unwrap_or("common");
        validation.set_issuer(&[
            &format!("https://login.microsoftonline.com/{}/v2.0", tenant_id),
            &format!("https://sts.windows.net/{}/", tenant_id),
        ]);
        validation.set_audience(&[&self.config.client_id]);

        let token_data = match decode::<Claims>(token.secret(), &decoding_key, &validation) {
            Ok(data) => data,
            Err(e) => {
                log::error!("Failed to decode JWT: {}", e);
                return false;
            }
        };

        log::info!("Token validated successfully for user: {:?}", token_data.claims.preferred_username);
        true
    }

    pub fn introspect_username(&self, token: &AccessToken) -> Result<String> {
        self.validate_token_claims(token, "dummy", "dummy");
        let parts: Vec<&str> = token.secret().split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid JWT structure").into());
        }
        let payload = base64::engine::general_purpose::URL_SAFE.decode(pad_base64(parts[1]))?;
        let json: Value = serde_json::from_slice(&payload)?;
        if let Some(username) = json.get("preferred_username").or_else(|| json.get("email")) {
            Ok(username.as_str().unwrap_or("anonymous").to_string())
        } else {
            return Err(anyhow::anyhow!("User name not found in token claims").into());
        }
    }
}

fn pad_base64(input: &str) -> String {
    let rem = input.len() % 4;
    if rem == 0 {
        input.to_string()
    } else {
        let padding = 4 - rem;
        format!("{}{}", input, "=".repeat(padding))
    }
}

fn valid_user(remote_username: &str, local_username: &str) -> bool {
    if remote_username == local_username && remote_username != "root" {
        return true;
    }
    log::warn!(
        "Invalid username: remote: {} -> local: {}",
        remote_username,
        &local_username
    );
    false
}
