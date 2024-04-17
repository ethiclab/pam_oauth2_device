mod config;
mod oauth_device;

use crate::config::read_config;
use crate::oauth_device::*;
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_OFF};

use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use qrcode::render::unicode;
use qrcode::QrCode;
use simplelog::*;
use std::collections::HashMap;
use std::ffi::CStr;
use std::thread::sleep;
use std::time::Duration;

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
            OAuthClient::new(&config),
            "Failed to create OAuthClient",
            PamResultCode::PAM_SYSTEM_ERR
        );

        let device_code_resp = or_pam_err!(
            oauth_client.device_code_req(),
            "Failed to comunicate with device endpoint",
            PamResultCode::PAM_AUTH_ERR
        );

        pam_try!(conv.send(
            PAM_PROMPT_ECHO_OFF,
            &format_user_prompt(
                &device_code_resp.verification_uri_complete,
                "Press \"ENTER\" after successful authentication: "
            )
        ));

        let token_try;
        loop {
            token_try = match oauth_client.get_token(&device_code_resp.device_code) {
                Err(e) if e.to_string() == "authorization_pending" => {
                    sleep(Duration::from_secs(device_code_resp.interval)); // Wait for the OAuth provider-specified time interval
                    pam_try!(conv.send(
                        PAM_PROMPT_ECHO_OFF,
                        &format_user_prompt(
                            &device_code_resp.verification_uri_complete,
                            "Try again and press \"ENTER\": "
                        )
                    ));
                    log::warn!(
                        "{e} for {user}. Next try in: {} secs...",
                        &device_code_resp.interval
                    );
                    continue;
                }
                re => re,
            };
            break;
        }

        let token = or_pam_err!(
            token_try,
            "Failed to resolve token response",
            PamResultCode::PAM_AUTH_ERR
        );

        let token = or_pam_err!(
            oauth_client.introspect(&token.access_token),
            "Failed to validate access_token",
            PamResultCode::PAM_AUTH_ERR
        );

        if token.is_active()
            && token.validate_scope(oauth_client.scope)
            && token.validate_username(&user)
            && token.validate_exp()
        {
            log::info!(
                "Authentication successful for remote user: {} -> local user: {user}",
                token.username.unwrap() //it is safe cause of token.validate_username
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

fn format_user_prompt(verification_uri_complete: &String, msg: &str) -> String {
    let qrcode = match qr_code(verification_uri_complete) {
        Err(e) => {
            log::warn!("Failed to create QR code: {e}");
            String::default()
        }
        Ok(qr) => qr,
    };

    format!(
        "\n{}\n{}\n{}\n{}",
        qrcode,
        "Scan QR code above or login via provided link in your web browser:",
        verification_uri_complete,
        msg
    )
}
