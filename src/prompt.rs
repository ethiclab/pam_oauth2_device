use std::fmt::{Debug, Display};

use oauth2::StandardDeviceAuthorizationResponse;
use oauth2::{UserCode, VerificationUriComplete};
use qrcode::render::unicode;
use qrcode::QrCode;

use crate::config::Messages;

struct QrString(String);

impl QrString {
    pub fn new(s: String) -> Self {
        Self(s)
    }
    pub fn secret(&self) -> &String {
        &self.0
    }
}

// log::debug would not compromise user verification_uri_complete
impl Debug for QrString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QrString([redacted])")
    }
}

#[derive(Debug)]
pub struct UserPrompt {
    qrcode: Option<QrString>,
    verification_uri_complete: Option<VerificationUriComplete>,
    verification_uri: String,
    user_code: UserCode,
    messages: Messages,
}

impl UserPrompt {
    pub fn new(
        device_code_resp: &StandardDeviceAuthorizationResponse,
        messages: &Messages,
    ) -> Self {
        Self {
            qrcode: None,
            verification_uri_complete: device_code_resp.verification_uri_complete().cloned(),
            verification_uri: device_code_resp.verification_uri().to_string(),
            user_code: device_code_resp.user_code().to_owned(),
            messages: messages.clone(),
        }
    }

    pub fn generate_qr(&mut self) {
        let qrcode: Option<QrString>;

        if let Some(verification_uri_complete) = &self.verification_uri_complete {
            qrcode = match qr_code(&verification_uri_complete.secret()) {
                Err(e) => {
                    log::warn!("Failed to create QR code: {e}");
                    None
                }
                Ok(qr) => Some(QrString::new(qr)),
            };
        } else {
            qrcode = match qr_code(&self.verification_uri) {
                Err(e) => {
                    log::warn!("Failed to create QR code: {e}");
                    None
                }
                Ok(qr) => Some(QrString::new(qr)),
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
                qr.secret(),
                &self.messages.prompt_complete,
                url.secret(),
                &self.messages.prompt_enter
            ),
            (None, Some(url)) => write!(
                f,
                "\n{}\n{}\n{}",
                &self.messages.prompt_no_qr_complete,
                url.secret(),
                &self.messages.prompt_enter
            ),
            (Some(qr), None) => write!(
                f,
                "\n{}\n{}\n{}\n{}\n{}\n{}",
                qr.secret(),
                &self.messages.prompt_incomplete,
                self.verification_uri,
                &self.messages.prompt_code,
                self.user_code.secret(),
                &self.messages.prompt_enter
            ),
            (None, None) => write!(
                f,
                "\n{}\n{}\n{}\n{}\n{}",
                &self.messages.prompt_no_qr_incomplete,
                self.verification_uri,
                &self.messages.prompt_code,
                self.user_code.secret(),
                &self.messages.prompt_enter
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

    Ok(qr_text)
}
