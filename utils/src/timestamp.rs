use anyhow::Context;
use chrono;

/// Try to parse an RFC 3339, warn on error.
pub fn try_deserialize_timestamp(t: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    match chrono::DateTime::parse_from_rfc3339(t).context("Parsing timestamp") {
        Ok(t) => Some(t.into()),
        Err(e) => {
            tracing::warn!("Invalid timestamp in image: {:#}", e);
            None
        }
    }
}
