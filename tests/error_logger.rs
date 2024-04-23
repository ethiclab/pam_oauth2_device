use pam_oauth2_device::error_logger::Logger;

type DynErr = Box<dyn std::error::Error>;

pub(crate) struct TestLogger {
    pub msg: String,
}

#[allow(dead_code)]
impl TestLogger {
    pub fn new() -> Self {
        Self {
            msg: String::default(),
        }
    }
}

impl Logger for TestLogger {
    fn handle_error(&mut self, fail: DynErr, msg: &'static str) {
        self.msg = msg.to_string();
        let mut cur_fail: Option<&dyn std::error::Error> = Some(&*fail);
        while let Some(cause) = cur_fail {
            self.msg += &format!("\n    caused by: {}", cause);
            cur_fail = cause.source();
        }
    }
}
