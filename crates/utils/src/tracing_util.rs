//! Helpers related to tracing, used by main entrypoints

use tracing_subscriber::prelude::*;

/// Initialize tracing with the default configuration.
pub fn initialize_tracing() {
    // Try to use journald subscriber if we're running under systemd
    if let Ok(()) = std::env::var("JOURNAL_STREAM").map(|_| ()) {
        if let Ok(subscriber) = tracing_journald::layer() {
            tracing_subscriber::registry()
                .with(subscriber)
                .with(tracing_subscriber::EnvFilter::from_default_env())
                .init();
            return;
        }
    }

    // Fall back to the previous setup if journald isn't available
    // Don't include timestamps and such because they're not really useful and
    // too verbose, and plus several log targets such as journald will already
    // include timestamps.
    let format = tracing_subscriber::fmt::format()
        .without_time()
        .with_target(false)
        .compact();
    // Log to stderr by default
    tracing_subscriber::fmt()
        .event_format(format)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}
