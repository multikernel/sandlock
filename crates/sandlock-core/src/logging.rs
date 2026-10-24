//! Opt-in stderr sink for the library's diagnostics, for the sandlock binaries.

struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().starts_with("sandlock") && metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("sandlock: {}", record.args());
        }
    }

    fn flush(&self) {}
}

/// Print sandlock's info and warning diagnostics to stderr. A no-op when the
/// process already installed a logger.
pub fn log_to_stderr() {
    if log::set_logger(&StderrLogger).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}
