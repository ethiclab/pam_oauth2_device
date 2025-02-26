use std::sync::{Arc, LazyLock, Mutex};

use log::{set_boxed_logger, set_max_level, LevelFilter, Log, SetLoggerError};
use pam_oauth2_device::error_logger::Logger;

#[allow(dead_code)]
pub(crate) static LOGGER: LazyLock<Arc<Mutex<TestLogger>>> =
    LazyLock::new(|| Arc::new(Mutex::new(init(log::LevelFilter::Info).unwrap())));

#[allow(dead_code)]
type DynErr = Box<dyn std::error::Error>;

#[derive(Clone)]
pub(crate) struct TestLogger {
    pub msg: Arc<Mutex<String>>,
    level: LevelFilter,
}

#[allow(dead_code)]
impl TestLogger {
    pub fn new(level: LevelFilter) -> Self {
        Self {
            msg: Arc::new(Mutex::new(String::new())),
            level,
        }
    }

    pub fn msg(&self) -> String {
        let msg = self.msg.lock().unwrap();
        msg.clone()
    }
}
#[allow(dead_code)]
pub(crate) fn init(level: LevelFilter) -> Result<TestLogger, SetLoggerError> {
    let logger = TestLogger::new(level);
    set_boxed_logger(Box::new(logger.clone()))?;
    set_max_level(level);
    Ok(logger)
}

impl Log for TestLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let mut msg = self.msg.lock().unwrap();
            *msg = record.args().to_string()
        }
    }

    fn flush(&self) {}
}

impl Logger for TestLogger {}
