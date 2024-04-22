mod utils;

use mockito::Server;
use oauth2::{basic::BasicTokenType, TokenResponse};
use pam_oauth2_device::oauth_device::{handle_error, OAuthClient};
use utils::{http_mock_device_complete, http_mock_token_200, http_mock_token_403, parse_config};

#[test]
fn token_basic() {
    let mut server = Server::new();
    let url = server.url();

    let config = parse_config(&url, None, true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_complete(&mut server);
    http_mock_token_200(&mut server);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details).unwrap();

    assert_eq!(token.access_token().secret(), "mocking_access_token");
    assert_eq!(
        token.refresh_token().unwrap().secret(),
        "mocking_refresh_token"
    );
    assert_eq!(token.token_type(), &BasicTokenType::Bearer);
    assert_eq!(token.expires_in().unwrap().as_secs(), 86400);
}

#[test]
fn token_403() {
    let mut server = Server::new();
    let url = server.url();

    let config = parse_config(&url, None, true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_complete(&mut server);
    http_mock_token_403(&mut server);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details);

    assert_eq!(token.unwrap_err().to_string(), "dupa");
}
