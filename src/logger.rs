use log::LevelFilter;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode, WriteLogger};
use std::fs::OpenOptions;
use std::sync::Once;

type DynErr = Box<dyn std::error::Error>;

static LOG_INIT: Once = Once::new();

pub struct DefaultLogger;

pub trait Logger {
    fn handle_error(fail: DynErr, msg: &'static str) {
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

impl DefaultLogger {
    pub fn init(log_path: &str, log_level: &str) {
        LOG_INIT.call_once(|| {
            let log_level = match log_level {
                "info" => LevelFilter::Info,
                "warn" => LevelFilter::Warn,
                "error" => LevelFilter::Error,
                "debug" => LevelFilter::Debug,
                "trace" => LevelFilter::Trace,
                _ => LevelFilter::Info,
            };

            let log_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
                .expect("Failed to open log file");

            CombinedLogger::init(vec![
                //TermLogger::new(
                //log_level,
                //Config::default(),
                //TerminalMode::Mixed,
                //ColorChoice::Auto,
                //),
                WriteLogger::new(log_level, Config::default(), log_file),
            ])
            .expect("Failed to inicialize logging!");
        })
    }
}
