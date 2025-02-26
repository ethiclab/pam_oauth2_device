type DynErr = Box<dyn std::error::Error>;

pub struct DefaultLogger;

pub trait Logger {
    fn handle_error(&self, fail: DynErr, msg: &'static str) {
        let mut err_msg = msg.to_string();
        let mut cur_fail: Option<&dyn std::error::Error> = Some(&*fail);
        while let Some(cause) = cur_fail {
            err_msg += &format!("\n    caused by: {}", cause);
            cur_fail = cause.source();
        }
        log::error!("{}", err_msg);
    }
}

impl Logger for DefaultLogger {}
