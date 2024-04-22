use pam_oauth2_device::config::Config;
use url::Url;

#[allow(dead_code)]
pub(crate) fn parse_config(url: &String, scope: Option<String>, qr: bool) -> Config {
    Config {
        client_id: "test".to_string(),
        client_secret: "test".to_string(),
        oauth_auth_url: Url::parse(&format!("{}/{}", url, "auth")).unwrap(),
        oauth_device_url: Url::parse(&format!("{}/{}", url, "device")).unwrap(),
        oauth_token_url: Url::parse(&format!("{}/{}", url, "token")).unwrap(),
        oauth_token_introspect_url: Url::parse(&format!("{}/{}", url, "introspect")).unwrap(),
        scope,
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
pub(crate) fn http_mock_token_200(server: &mut mockito::ServerGuard) {
    server
        .mock("POST", "/token")
        .with_status(200)
        .with_body(
            r#"{
        "access_token": "mocking_access_token",
        "refresh_token": "mocking_refresh_token",
        "id_token": "mocking_id_token",
        "token_type": "Bearer",
        "expires_in": 86400
    }"#,
        )
        .create();
}

#[allow(dead_code)]
pub(crate) fn http_mock_token_403(server: &mut mockito::ServerGuard) {
    server
        .mock("POST", "/token")
        .with_status(500)
        .with_body(
            r#"{
        "error": "access_denied",
        "error_description": "Authorization for user is still pending."
    }"#,
        )
        .create();
}
