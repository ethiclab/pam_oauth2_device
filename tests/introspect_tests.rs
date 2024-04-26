mod error_logger;
mod utils;

use error_logger::TestLogger;
use mockito::Server;
use oauth2::{Scope, TokenIntrospectionResponse, TokenResponse};
use pam_oauth2_device::error_logger::Logger;
use pam_oauth2_device::oauth_device::OAuthClient;
use utils::{http_mock_device_complete, http_mock_token_with_status, mock_config};

use crate::utils::http_mock_introspect_with_status;

#[test]
fn introspect_basic_active() {
    let mut server = Server::new();
    let url = server.url();

    let config = mock_config(&url, "openid profile".to_string(), true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_complete(&mut server);
    http_mock_token_with_status(&mut server, 200);
    http_mock_introspect_with_status(&mut server, 200, true);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_eq!(
        *token.scopes().unwrap(),
        vec![
            Scope::new("openid".to_string()),
            Scope::new("profile".to_string())
        ]
    );
    assert_eq!(oauth_client.validate_token(&token, "test"), true);
    assert_eq!(oauth_client.validate_token(&token, "non-valid-user"), false);
}

#[test]
fn introspect_active_other_scope_order() {
    let mut server = Server::new();
    let url = server.url();

    let config = mock_config(&url, "profile openid".to_string(), true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_complete(&mut server);
    http_mock_token_with_status(&mut server, 200);
    http_mock_introspect_with_status(&mut server, 200, true);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_eq!(
        *token.scopes().unwrap(),
        vec![
            Scope::new("openid".to_string()),
            Scope::new("profile".to_string())
        ]
    );
    assert_eq!(oauth_client.validate_token(&token, "test"), true);
    assert_eq!(oauth_client.validate_token(&token, "non-valid-user"), false);
}

#[test]
fn introspect_wrong_scope_active() {
    let mut server = Server::new();
    let url = server.url();

    let config = mock_config(&url, "wrong_scope".to_string(), true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_complete(&mut server);
    http_mock_token_with_status(&mut server, 200);
    http_mock_introspect_with_status(&mut server, 200, true);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_eq!(
        *token.scopes().unwrap(),
        vec![
            Scope::new("openid".to_string()),
            Scope::new("profile".to_string())
        ]
    );
    assert_eq!(oauth_client.validate_token(&token, "test"), false);
    assert_eq!(oauth_client.validate_token(&token, "non-valid-user"), false);
}

#[test]
fn introspect_basic_inactive() {
    let mut server = Server::new();
    let url = server.url();

    let config = mock_config(&url, "openid profile".to_string(), true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_complete(&mut server);
    http_mock_token_with_status(&mut server, 200);
    http_mock_introspect_with_status(&mut server, 200, false);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), false);
    assert_eq!(oauth_client.validate_token(&token, "test"), false);
}

#[test]
fn introspect_common_error() {
    let mut server = Server::new();
    let url = server.url();
    let mut logger = TestLogger::new();

    let config = mock_config(&url, "openid profile".to_string(), true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_complete(&mut server);
    http_mock_token_with_status(&mut server, 200);
    http_mock_introspect_with_status(&mut server, 401, false);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details).unwrap();
    let token = oauth_client.introspect(token.access_token());
    assert!(token.is_err());

    let _ = token.map_err(|err| logger.handle_error(err, "Failed to intropsect user token"));

    assert_eq!(
        logger.msg,
        "Failed to intropsect user token\n    caused by: Server returned error response"
    );
}

#[test]
fn introspect_other_error() {
    let mut server = Server::new();
    let url = server.url();
    let mut logger = TestLogger::new();

    let config = mock_config(&url, "openid profile".to_string(), true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_complete(&mut server);
    http_mock_token_with_status(&mut server, 200);
    http_mock_introspect_with_status(&mut server, 101, false);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details).unwrap();
    let token = oauth_client.introspect(token.access_token());
    assert!(token.is_err());

    let _ = token.map_err(|err| logger.handle_error(err, "Failed to intropsect user token"));

    assert_eq!(
        logger.msg,
        "Failed to intropsect user token\n    caused by: Other error: Server returned empty error response"
    );
}
