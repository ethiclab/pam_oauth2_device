type DynErr = Box<dyn std::error::Error>;

pub struct DefaultLogger;

pub trait Logger {
    // Self is mutable cause of TestLogger. See tests/error_logger
    fn handle_error(&mut self, fail: DynErr, msg: &'static str);
}

impl Logger for DefaultLogger {
    fn handle_error(&mut self, fail: DynErr, msg: &'static str) {
        let mut err_msg = msg.to_string();
        let mut cur_fail: Option<&dyn std::error::Error> = Some(&*fail);
        while let Some(cause) = cur_fail {
            err_msg += &format!("\n    caused by: {}", cause);
            cur_fail = cause.source();
        }
        log::error!("{}", err_msg);
    }
}
