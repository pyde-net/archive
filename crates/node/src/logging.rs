use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the tracing subscriber based on config.
pub fn init(level: &str, json: bool) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

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

/// Initialize tracing to a file instead of stdout. Used when the
/// TUI dashboard takes over the terminal — logs still need to go
/// somewhere greppable / shippable, so they land at the given
/// path (truncated on each start). ANSI colours are stripped so
/// the file isn't littered with escape codes.
pub fn init_file(level: &str, json: bool, path: &std::path::Path) -> std::io::Result<()> {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    if json {
        fmt()
            .with_env_filter(filter)
            .json()
            .with_writer(file)
            .with_target(true)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .init();
    } else {
        fmt()
            .with_env_filter(filter)
            .with_writer(file)
            .with_ansi(false)
            .with_target(true)
            .with_thread_ids(false)
            .init();
    }
    Ok(())
}
