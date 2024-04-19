use std::fmt::Display;

use oauth2::StandardDeviceAuthorizationResponse;
use qrcode::render::unicode;
use qrcode::QrCode;

pub struct UserPrompt {
    qrcode: Option<String>,
    verification_uri_complete: Option<String>,
    verification_uri: String,
    user_code: String,
    msg: String,
}

impl UserPrompt {
    pub fn new(device_code_resp: &StandardDeviceAuthorizationResponse, msg: &str) -> Self {
        Self {
            qrcode: None,
            verification_uri_complete: device_code_resp
                .verification_uri_complete()
                .map_or(None, |v| Some(v.secret().to_string())),
            verification_uri: device_code_resp.verification_uri().to_string(),
            user_code: device_code_resp.user_code().secret().to_string(),
            msg: msg.to_string(),
        }
    }

    pub fn generate_qr(&mut self) {
        let qrcode: Option<String>;

        if let Some(verification_uri_complete) = &self.verification_uri_complete {
            qrcode = match qr_code(&verification_uri_complete) {
                Err(e) => {
                    log::warn!("Failed to create QR code: {e}");
                    None
                }
                Ok(qr) => Some(qr),
            };
        } else {
            qrcode = match qr_code(&self.verification_uri) {
                Err(e) => {
                    log::warn!("Failed to create QR code: {e}");
                    None
                }
                Ok(qr) => Some(qr),
            }
        }
        self.qrcode = qrcode;
    }
}

impl Display for UserPrompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.qrcode, &self.verification_uri_complete) {
            (Some(qr), Some(url)) => write!(
                f,
                "\n{}\n{}\n{}\n{}",
                qr,
                "Scan QR code above or login via provided link in your web browser:",
                url,
                self.msg
            ),
            (None, Some(url)) => write!(
                f,
                "\n{}\n{}\n{}",
                "Login via provided link in your web browser:", url, self.msg
            ),
            (Some(qr), None) => write!(
                f,
                "\n{}\n{}\n{}\n{}\n{}\n{}",
                qr,
                "Scan QR code above or open provided link in your web browser:",
                self.verification_uri,
                "And enter this uniqe code:",
                self.user_code,
                self.msg
            ),
            (None, None) => write!(
                f,
                "\n{}\n{}\n{}\n{}\n{}",
                "Open provided link in your web browser:",
                self.verification_uri,
                "And enter this uniqe code:",
                self.user_code,
                self.msg
            ),
        }
    }
}
pub fn qr_code(url: &String) -> Result<String, Box<dyn std::error::Error>> {
    let qr = QrCode::new(&url)?;

    let qr_text = qr
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();

    Ok(format!("{}", qr_text))
}
