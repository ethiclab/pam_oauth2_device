use pam_oauth2_device::config::Config;
use url::Url;

#[allow(dead_code)]
pub(crate) fn mock_config(url: &String, scopes: String, qr: bool) -> Config {
    Config {
        client_id: "test".to_string(),
        client_secret: "test".to_string(),
        oauth_auth_url: Url::parse(&format!("{}/{}", url, "auth")).unwrap(),
        oauth_device_url: Url::parse(&format!("{}/{}", url, "device")).unwrap(),
        oauth_token_url: Url::parse(&format!("{}/{}", url, "token")).unwrap(),
        oauth_token_introspect_url: Url::parse(&format!("{}/{}", url, "introspect")).unwrap(),
        scopes,
        qr_enabled: qr,
    }
}

#[allow(dead_code)]
pub(crate) fn http_mock_device_basic(server: &mut mockito::ServerGuard) {
    server
        .mock("POST", "/device")
        .with_status(200)
        .with_body(
            r#"{
            "device_code": "mocking_device_code",
            "user_code": "mocking_user_code",
            "verification_uri": "https://mocking.uri/",
            "expires_in": 3600,
            "interval": 5
        }"#,
        )
        .create();
}

#[allow(dead_code)]
pub(crate) fn http_mock_device_complete(server: &mut mockito::ServerGuard) {
    server
        .mock("POST", "/device")
        .with_status(200)
        .with_body(
            r#"{
            "device_code": "mocking_device_code",
            "user_code": "mocking_user_code",
            "verification_uri": "https://mocking.uri/",
            "verification_uri_complete": "https://mocking.uri/mocking_user_code",
            "expires_in": 3600,
            "interval": 5
        }"#,
        )
        .create();
}

#[allow(dead_code)]
pub(crate) fn http_mock_token_with_status(server: &mut mockito::ServerGuard, status: usize) {
    let body = match status {
        200..=299 => {
            r#"{
        "access_token": "mocking_access_token",
        "refresh_token": "mocking_refresh_token",
        "id_token": "mocking_id_token",
        "token_type": "Bearer",
        "expires_in": 86400
            }"#
        }
        _ => {
            r#"{
        "error": "access_denied",
        "error_description": "Authorization for user is still pending."
            }"#
        }
    };
    server
        .mock("POST", "/token")
        .with_status(status)
        .with_body(body)
        .create();
}

#[allow(dead_code)]
pub(crate) fn http_mock_introspect_with_status(
    server: &mut mockito::ServerGuard,
    status: usize,
    active: bool,
) {
    let body = match status {
        200..=299 => format!(
            r#"{{
        "active": {},
        "scope": "openid profile",
        "client_id": "test",
        "username": "test",
        "token_type": "Bearer",
        "exp": 32481939912,
        "iat": 1713949569,
        "nbf": 1713949569,
        "aud": "test",
        "iss": "test"
            }}"#,
            active
        ),
        _ => {
            format!(
                r#"{{
        "error": "invalid_client",
        "error_description": "This client authentication was invalid"
            }}"#
            )
        }
    };
    server
        .mock("POST", "/introspect")
        .with_status(status)
        .with_body(body)
        .create();
}
