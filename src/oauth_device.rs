use crate::config::Config;
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::reqwest::http_client;
use oauth2::{
    AccessToken, AuthUrl, ClientId, ClientSecret, DeviceAuthorizationUrl, IntrospectionUrl,
    RedirectUrl, Scope, TokenIntrospectionResponse, TokenResponse, TokenUrl,
};

type DynErr = Box<dyn std::error::Error>;

pub struct OAuthClient {
    client: BasicClient,
    scope: Vec<Scope>,
}

impl OAuthClient {
    pub fn new(c: &Config) -> Result<Self, DynErr> {
        let client_id = ClientId::new(c.client_id.clone());
        let client_secret = ClientSecret::new(c.client_secret.clone());
        let auth_url = AuthUrl::from_url(c.oauth_auth_url.clone());
        let token_url = TokenUrl::from_url(c.oauth_token_url.clone());
        let device_url = DeviceAuthorizationUrl::from_url(c.oauth_device_url.clone());
        let introspect_url = IntrospectionUrl::from_url(c.oauth_token_introspect_url.clone());
        let redirect_url = RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string())?;
        let scope = c
            .get_scope()
            .split_whitespace()
            .map(|s| Scope::new(s.to_string()))
            .collect();

        let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_device_authorization_url(device_url)
            .set_introspection_uri(introspect_url)
            .set_redirect_uri(redirect_url);

        Ok(Self { client, scope })
    }

    pub fn device_code(&self) -> Result<StandardDeviceAuthorizationResponse, DynErr> {
        let details: StandardDeviceAuthorizationResponse = self
            .client
            .exchange_device_code()?
            .add_scopes(self.scope.clone())
            .request(http_client)?;
        Ok(details)
    }

    pub fn get_token(
        &self,
        details: &StandardDeviceAuthorizationResponse,
    ) -> Result<impl TokenResponse<BasicTokenType>, DynErr> {
        let token = self.client.exchange_device_access_token(details).request(
            http_client,
            std::thread::sleep,
            None,
        )?;
        Ok(token)
    }

    pub fn introspect(
        &self,
        token: &AccessToken,
    ) -> Result<impl TokenIntrospectionResponse<BasicTokenType>, DynErr> {
        let introspect = self.client.introspect(token)?.request(http_client)?;
        Ok(introspect)
    }

    pub fn validate_token(
        &self,
        token: &impl TokenIntrospectionResponse<BasicTokenType>,
        user: &String,
    ) -> bool {
        if !token.active() {
            log::warn!("User token inactive!");
            return false;
        }

        let username_valid = token.username().map_or_else(
            || {
                log::warn!("No username provided");
                false
            },
            |username| {
                if username != user {
                    log::warn!("Invalid username: remote: {} -> local: {}", username, &user);
                    false
                } else {
                    true
                }
            },
        );

        let scope_valid = token.scopes().map_or_else(
            || {
                log::warn!("No scope provided");
                false
            },
            |scopes| {
                // Scopes order doesn't matter according to RFC 6749
                if !self.scope.iter().all(|s| scopes.contains(s)) {
                    log::warn!("Invalid scopes for user {}: {:?}", &user, self.scope,);
                    false
                } else {
                    true
                }
            },
        );

        let exp_valid = token.exp().map_or_else(
            || {
                log::warn!("No expiration time provided");
                false
            },
            |exp| exp > chrono::Local::now(),
        );

        if !exp_valid {
            log::warn!("Token has expired for user {}", &user);
        }

        username_valid && scope_valid && exp_valid
    }
}
