use file_rotate::{
    compression::Compression,
    suffix::{AppendTimestamp, DateFrom, FileLimit},
    ContentLimit, FileRotate, TimeFrequency,
};
use log::LevelFilter;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode, WriteLogger};

type DynErr = Box<dyn std::error::Error>;

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
        let log_level = match log_level {
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Info,
        };
        let log_file = FileRotate::new(
            log_path,
            AppendTimestamp::with_format(
                "%Y-%m-%d",
                FileLimit::MaxFiles(7),
                DateFrom::DateYesterday,
            ),
            ContentLimit::Time(TimeFrequency::Daily),
            Compression::None,
            #[cfg(unix)]
            None,
        );
        CombinedLogger::init(vec![
            TermLogger::new(
                log_level,
                Config::default(),
                TerminalMode::Mixed,
                ColorChoice::Auto,
            ),
            WriteLogger::new(log_level, Config::default(), log_file),
        ])
        .expect("Failed to inicialize logging!");
    }
}
