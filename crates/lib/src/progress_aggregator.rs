//! Progress aggregator that implements JSON-first progress architecture
//! All progress flows through JSON events before being rendered or output

use anyhow::Result;
use std::io::IsTerminal;

use crate::progress_jsonl::{Event, ProgressWriter};
use crate::progress_renderer::{ProgressFilter, ProgressRenderer};

/// Unified progress system that emits JSON events and optionally renders them visually
/// This implements the JSON-first architecture where indicatif becomes a consumer of JSON events
pub struct ProgressAggregator {
    json_writer: Option<ProgressWriter>,
    renderer: Option<ProgressRenderer>,
}

impl ProgressAggregator {
    /// Create a new progress aggregator
    pub fn new(json_writer: Option<ProgressWriter>, visual_filter: Option<ProgressFilter>) -> Self {
        let renderer = if std::io::stderr().is_terminal() && visual_filter.is_some() {
            Some(ProgressRenderer::new(visual_filter.unwrap()))
        } else {
            None
        };

        Self {
            json_writer,
            renderer,
        }
    }

    /// Send a progress event - this is the core method that implements JSON-first architecture
    pub async fn send_event(&mut self, event: Event<'_>) -> Result<()> {
        // 1. Always emit JSON first (if enabled)
        if let Some(ref writer) = self.json_writer {
            writer.send_lossy(event.clone()).await;
        }

        // 2. Then render visually (if enabled)
        if let Some(ref mut renderer) = self.renderer {
            renderer.handle_event(&event)?;
        }

        Ok(())
    }

    /// Finish all progress and clean up
    pub fn finish(&mut self) {
        if let Some(ref mut renderer) = self.renderer {
            renderer.finish();
        }
    }
}

/// Helper to create progress aggregators for common use cases
pub struct ProgressAggregatorBuilder {
    json_writer: Option<ProgressWriter>,
    visual_filter: Option<ProgressFilter>,
}

impl ProgressAggregatorBuilder {
    pub fn new() -> Self {
        Self {
            json_writer: None,
            visual_filter: None,
        }
    }

    /// Enable JSON output to the given writer
    pub fn with_json(mut self, writer: ProgressWriter) -> Self {
        self.json_writer = Some(writer);
        self
    }

    /// Enable visual progress with the given filter
    pub fn with_visual(mut self, filter: ProgressFilter) -> Self {
        self.visual_filter = Some(filter);
        self
    }

    /// Build the aggregator
    pub fn build(self) -> ProgressAggregator {
        ProgressAggregator::new(self.json_writer, self.visual_filter)
    }
}

impl Default for ProgressAggregatorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress_jsonl::Event;
    use std::borrow::Cow;

    #[tokio::test]
    async fn test_json_first_architecture() -> Result<()> {
        // Create an aggregator that outputs both JSON and visual progress
        let mut aggregator = ProgressAggregatorBuilder::new()
            .with_visual(ProgressFilter::All)
            .build();

        // Send a progress event
        let event = Event::ProgressBytes {
            task: Cow::Borrowed("test"),
            description: Cow::Borrowed("Testing progress"),
            id: Cow::Borrowed("test-id"),
            bytes_cached: 0,
            bytes: 50,
            bytes_total: 100,
            steps_cached: 0,
            steps: 1,
            steps_total: 2,
            subtasks: vec![],
        };

        aggregator.send_event(event).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_task_filtering() -> Result<()> {
        // Create an aggregator that only shows "pulling" tasks
        let mut aggregator = ProgressAggregatorBuilder::new()
            .with_visual(ProgressFilter::TasksMatching(vec!["pulling".to_string()]))
            .build();

        // Send a pulling event (should be shown)
        let pulling_event = Event::ProgressBytes {
            task: Cow::Borrowed("pulling"),
            description: Cow::Borrowed("Pulling image"),
            id: Cow::Borrowed("image:latest"),
            bytes_cached: 0,
            bytes: 25,
            bytes_total: 100,
            steps_cached: 0,
            steps: 1,
            steps_total: 3,
            subtasks: vec![],
        };

        // Send an installing event (should be filtered out visually)
        let installing_event = Event::ProgressSteps {
            task: Cow::Borrowed("installing"),
            description: Cow::Borrowed("Installing package"),
            id: Cow::Borrowed("package"),
            steps_cached: 0,
            steps: 1,
            steps_total: 5,
            subtasks: vec![],
        };

        aggregator.send_event(pulling_event).await?;
        aggregator.send_event(installing_event).await?;

        Ok(())
    }
}
