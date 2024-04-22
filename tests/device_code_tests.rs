mod utils;
use crate::utils::{http_mock_device_basic, http_mock_device_complete, parse_config};
use mockito::Server;
use pam_oauth2_device::oauth_device::OAuthClient;
use pam_oauth2_device::prompt::{qr_code, UserPrompt};

#[test]
fn device_basic_uri() {
    let mut server = Server::new();
    let url = server.url();

    let config = parse_config(&url, None, true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_basic(&mut server);

    let resp = oauth_client.device_code().unwrap();

    let mut prompt = UserPrompt::new(&resp, "");

    assert_eq!(resp.device_code().secret(), "mocking_device_code");
    assert_eq!(resp.user_code().secret(), "mocking_user_code");
    assert_eq!(resp.verification_uri().to_string(), "https://mocking.uri/");
    assert_eq!(resp.expires_in().as_secs(), 3600);
    assert_eq!(resp.interval().as_secs(), 5);

    // No QR code generated
    assert_eq!(prompt.to_string(), "\nOpen provided link in your web browser:\nhttps://mocking.uri/\nAnd enter this uniqe code:\nmocking_user_code\n");

    prompt.generate_qr();

    // With QR code generated
    assert_eq!(
        prompt.to_string(),
        format!(
            "\n{}\n{}",
            qr_code(&"https://mocking.uri/".to_string()).unwrap(),
            "Scan QR code above or open provided link in your web browser:\nhttps://mocking.uri/\nAnd enter this uniqe code:\nmocking_user_code\n"
        )
    );
}

#[test]
fn device_uri_complete() {
    let mut server = Server::new();
    let url = server.url();

    let config = parse_config(&url, None, true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    http_mock_device_complete(&mut server);

    let resp = oauth_client.device_code().unwrap();

    let mut prompt = UserPrompt::new(&resp, "");

    assert_eq!(resp.device_code().secret(), "mocking_device_code");
    assert_eq!(resp.user_code().secret(), "mocking_user_code");
    assert_eq!(resp.verification_uri().to_string(), "https://mocking.uri/");
    assert_eq!(
        resp.verification_uri_complete().unwrap().secret(),
        "https://mocking.uri/mocking_user_code"
    );
    assert_eq!(resp.expires_in().as_secs(), 3600);
    assert_eq!(resp.interval().as_secs(), 5);

    // No QR code generated
    assert_eq!(
        prompt.to_string(),
        "\nLogin via provided link in your web browser:\nhttps://mocking.uri/mocking_user_code\n"
    );

    prompt.generate_qr();
    // With QR code generated
    assert_eq!(
        prompt.to_string(),
        format!(
            "\n{}\nScan QR code above or login via provided link in your web browser:\nhttps://mocking.uri/mocking_user_code\n",
            qr_code(&"https://mocking.uri/mocking_user_code".to_string()).unwrap()
        )
    );
}

#[test]
fn err_500_device() {
    let mut server = Server::new();
    let url = server.url();

    let config = parse_config(&url, None, true);
    let oauth_client = OAuthClient::new(&config).unwrap();

    server
        .mock("POST", "/device")
        .with_status(500)
        .with_body(
            r#"{
        "error": "500 Internal Server Error" 
    }
        "#,
        )
        .create();

    let resp = oauth_client.device_code();

    assert!(resp.is_err());
    assert_eq!(
        resp.err().unwrap().to_string(),
        "Server returned error response"
    );
}
