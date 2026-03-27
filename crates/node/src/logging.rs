use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the tracing subscriber based on config.
pub fn init(level: &str, json: bool) {
    let filter = EnvFilter::try_new(level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if json {
        fmt()
            .with_env_filter(filter)
            .json()
            .with_target(true)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .init();
    } else {
        fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(false)
            .init();
    }
}
