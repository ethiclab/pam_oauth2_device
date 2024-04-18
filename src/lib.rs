mod config;
mod oauth_device;

use crate::config::read_config;
use crate::oauth_device::*;
use oauth2::{StandardDeviceAuthorizationResponse, TokenIntrospectionResponse, TokenResponse};
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_OFF};

use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use qrcode::render::unicode;
use qrcode::QrCode;
use simplelog::*;
use std::collections::HashMap;
use std::ffi::CStr;

struct PamOAuth2Device;
pam::pam_hooks!(PamOAuth2Device);

macro_rules! or_pam_err {
    ($res:expr, $error_message:expr, $pam_error:expr) => {
        match $res {
            Ok(o) => o,
            Err(e) => {
                log::error!("{}: {}", $error_message, e);
                return $pam_error;
            }
        }
    };
}

impl PamHooks for PamOAuth2Device {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        init_logs();
        let args = parse_args(&args);
        let default_config = "/etc/pam_oauth2_device/config.json".to_string();
        let config = read_config(args.get("config").unwrap_or(&default_config));
        let config = or_pam_err!(
            config,
            "Failed to read config file",
            PamResultCode::PAM_SYSTEM_ERR
        );

        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            Ok(None) => {
                unreachable!("No conv available");
            }
            Err(err) => {
                log::error!("Couldn't get pam_conv");
                return err;
            }
        };

        let user = pam_try!(pamh.get_user(None));
        log::info!("Trying to authenticate user: {user}");

        let oauth_client = or_pam_err!(
            OAuthClient::new(config),
            "Failed to create OAuthClient",
            PamResultCode::PAM_SYSTEM_ERR
        );

        let device_code_resp = or_pam_err!(
            oauth_client.device_code(),
            "Failed to comunicate with device endpoint",
            PamResultCode::PAM_AUTH_ERR
        );

        pam_try!(conv.send(
            PAM_PROMPT_ECHO_OFF,
            &format_user_prompt(
                &device_code_resp,
                "Press \"ENTER\" after successful authentication: "
            )
        ));

        let token = or_pam_err!(
            oauth_client.get_token(&device_code_resp),
            "Failed to get user token",
            PamResultCode::PAM_AUTH_ERR
        );

        let token = or_pam_err!(
            oauth_client.introspect(&token.access_token()),
            "Failed to introspect user token",
            PamResultCode::PAM_AUTH_ERR
        );

        if validate_token(&token, oauth_client, &user) {
            let username = token.username().unwrap(); //it is safe cause of token.validate_username
            log::info!(
                "Authentication successful for remote user: {} -> local user: {}",
                username,
                user
            );
            return PamResultCode::PAM_SUCCESS;
        }

        log::warn!("Login failed for user: {user}");

        PamResultCode::PAM_AUTH_ERR
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

fn parse_args(args: &[&CStr]) -> HashMap<String, String> {
    args.iter()
        .map(|&s| {
            let s = s.to_string_lossy().into_owned();
            let mut parts = s.splitn(2, '=');
            (
                parts.next().unwrap().to_string(),
                parts.next().unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn init_logs() {
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/pam_oauth2_device.log")
        .expect("Failed to open log file!");
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Warn,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(LevelFilter::Info, Config::default(), log_file),
    ])
    .expect("Failed to inicialize logging!");
}

fn qr_code(url: &String) -> Result<String, Box<dyn std::error::Error>> {
    let qr = QrCode::new(&url)?;

    let qr_text = qr
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();

    Ok(format!("{}", qr_text))
}

fn format_user_prompt(device_code_resp: &StandardDeviceAuthorizationResponse, msg: &str) -> String {
    if let Some(verification_uri_complete) = device_code_resp.verification_uri_complete() {
        let qrcode = match qr_code(&verification_uri_complete.secret()) {
            Err(e) => {
                log::warn!("Failed to create QR code: {e}");
                String::default()
            }
            Ok(qr) => qr,
        };
        return format!(
            "\n{}\n{}\n{}\n{}",
            qrcode,
            "Scan QR code above or login via provided link in your web browser:",
            verification_uri_complete.secret(),
            msg
        );
    } else {
        let qrcode = match qr_code(&device_code_resp.verification_uri().to_string()) {
            Err(e) => {
                log::warn!("Failed to create QR code: {e}");
                String::default()
            }
            Ok(qr) => qr,
        };
        return format!(
            "\n{}\n{}\n{}\n{}\n{}\n{}",
            qrcode,
            "Scan QR code above or open provided link in your web browser:",
            device_code_resp.verification_uri().to_string(),
            "And enter this uniqe code:",
            device_code_resp.user_code().secret(),
            msg
        );
    }
}
