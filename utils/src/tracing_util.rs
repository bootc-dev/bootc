//! Helpers related to tracing, used by main entrypoints

use std::sync::{Arc, OnceLock};
use tracing::Level;
use tracing_subscriber::{
    filter::LevelFilter, fmt, layer::SubscriberExt, reload, EnvFilter, Registry,
};

/// Global reload handle for dynamically updating log levels
static TRACING_RELOAD_HANDLE: OnceLock<Arc<reload::Handle<EnvFilter, Registry>>> = OnceLock::new();

/// Initialize tracing with the default configuration.
pub fn initialize_tracing() {
    // Create a reloadable EnvFilter: Use `RUST_LOG` if available, otherwise default to WARN
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(LevelFilter::WARN.to_string()));
    let (filter, reload_handle) = reload::Layer::new(env_filter);

    // Don't include timestamps and such because they're not really useful and
    // too verbose, and plus several log targets such as journald will already
    // include timestamps.
    let format = tracing_subscriber::fmt::format()
        .without_time()
        .with_target(false)
        .compact();

    // Create a subscriber with a reloadable filter and formatted output
    // Log to stderr by default
    let subscriber = Registry::default().with(filter).with(
        fmt::layer()
            .event_format(format)
            .with_writer(std::io::stderr),
    );

    // Set the subscriber globally
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    // Store the reload handle in a global OnceLock
    TRACING_RELOAD_HANDLE.set(Arc::new(reload_handle)).ok();
}

/// Update tracing log level dynamically.
pub fn update_tracing_log_level(log_level: Level) {
    if let Some(handle) = TRACING_RELOAD_HANDLE.get() {
        // Create new filter. Use `RUST_LOG` if available
        let new_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(log_level.to_string()));
        if let Err(e) = handle.modify(|filter| *filter = new_filter) {
            eprintln!("Failed to update log level: {}", e);
        }
    } else {
        panic!("Fatal error: Logging system not initialized. Ensure initialize_tracing() is called first.");
    }
}
