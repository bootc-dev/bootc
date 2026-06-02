//! Helpers related to tracing, used by main entrypoints

use tracing_subscriber::prelude::*;

/// Initialize tracing with the default configuration.
pub fn initialize_tracing() {
    // Always try to use journald subscriber if we're running as root;
    // This ensures key messages (info, warn, error) go to the journal
    let journald_layer = if rustix::process::getuid().is_root() {
        tracing_journald::layer()
            .ok()
            // Drop the default `F_` field prefix so our structured fields map to
            // native journal fields: `message_id` -> the well-known `MESSAGE_ID`
            // (queryable via `journalctl MESSAGE_ID=...`) and e.g.
            // `bootc.image.reference` -> `BOOTC_IMAGE_REFERENCE`.
            .map(|layer| {
                layer
                    .with_field_prefix(None)
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO)
            })
    } else {
        None
    };

    // Always add the stdout/stderr layer for RUST_LOG support
    // This preserves the existing workflow for users
    let format = tracing_subscriber::fmt::format()
        .without_time()
        .with_target(false)
        .compact();

    let fmt_layer = tracing_subscriber::fmt::layer()
        .event_format(format)
        .with_writer(std::io::stderr)
        .with_filter(tracing_subscriber::EnvFilter::from_default_env());

    // Build the registry with layers, handling the journald layer conditionally
    match journald_layer {
        Some(journald) => {
            tracing_subscriber::registry()
                .with(fmt_layer)
                .with(journald)
                .init();
        }
        None => {
            tracing_subscriber::registry().with(fmt_layer).init();
        }
    }
}
