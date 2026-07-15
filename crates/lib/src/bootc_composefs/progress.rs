//! Bridge composefs-rs's [`ProgressReporter`] callback API to bootc's own
//! progress infrastructure (interactive `indicatif` bars and the
//! `--progress-fd` JSON-Lines protocol).
//!
//! composefs-rs (`composefs::progress`) reports progress via a synchronous,
//! `Send + Sync` callback trait invoked directly from whatever task is
//! driving the pull. That's a poor fit for [`crate::progress_jsonl::ProgressWriter`],
//! whose API is `async`. We bridge the two by handing composefs-rs a trivial
//! reporter that forwards every [`ProgressEvent`] over an unbounded channel,
//! and processing that channel from a concurrently spawned Tokio task which
//! owns the `indicatif` state and the `ProgressWriter`. This mirrors the
//! existing ostree pull progress plumbing in `crate::deploy` (see
//! `handle_layer_progress_print`), which is channel-based for the same
//! reason.

use std::collections::HashMap;

use composefs_ctl::composefs::progress::{
    ComponentId, ProgressEvent, ProgressReporter, ProgressUnit, SharedReporter,
};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::progress_jsonl::{Event, ProgressWriter, SubTaskBytes};

/// Number of leading characters of a [`ComponentId`] (typically a
/// `sha256:`-prefixed layer digest) to show in terminal output.
const ID_DISPLAY_LEN: usize = 20;

/// Forwards [`ProgressEvent`]s from composefs-rs's synchronous callback onto
/// an unbounded channel for asynchronous processing.
struct ChannelReporter {
    tx: mpsc::UnboundedSender<ProgressEvent>,
}

impl ProgressReporter for ChannelReporter {
    fn report(&self, event: ProgressEvent) {
        // Errors mean the receiving task has already exited (e.g. the pull
        // was aborted); there's nothing useful to do at that point.
        let _ = self.tx.send(event);
    }
}

/// State tracked per in-flight component so we can render both an
/// `indicatif` bar and, for byte-oriented transfers, a JSON-Lines subtask.
struct ActiveComponent {
    unit: ProgressUnit,
    fetched: u64,
    total: Option<u64>,
    bar: ProgressBar,
}

/// Start bridging composefs-rs progress events into bootc's UI.
///
/// Returns a [`SharedReporter`] to pass as `PullOptions::progress`, and the
/// [`JoinHandle`] for the background task driving the UI. The task exits
/// once every clone of the returned reporter has been dropped (which
/// happens naturally when the `composefs_oci::pull` future completes and
/// drops its `PullOptions`); callers should `.await` the join handle after
/// awaiting the pull to ensure the terminal output is flushed before
/// proceeding, and to recover the (possibly-mutated) `ProgressWriter`.
pub(crate) fn spawn(
    quiet: bool,
    prog: ProgressWriter,
) -> (SharedReporter, JoinHandle<ProgressWriter>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let reporter: SharedReporter = std::sync::Arc::new(ChannelReporter { tx });
    let handle = tokio::spawn(drive_progress(rx, quiet, prog));
    (reporter, handle)
}

/// Truncate a [`ComponentId`] for compact display.
fn short_id(id: &ComponentId) -> String {
    let s = id.as_str();
    s.chars().take(ID_DISPLAY_LEN).collect()
}

fn bar_style(unit: ProgressUnit) -> ProgressStyle {
    let template = match unit {
        ProgressUnit::Bytes => {
            "[eta {eta}] {bar:40.cyan/blue} {binary_bytes:>9}/{binary_total_bytes:9} {msg}"
        }
        ProgressUnit::Items => "[eta {eta}] {bar:40.cyan/blue} {pos:>7}/{len:7} objects {msg}",
        // `ProgressUnit` is `#[non_exhaustive]`; fall back to a generic style
        // for any future variant.
        _ => "[eta {eta}] {bar:40.cyan/blue} {pos}/{len} {msg}",
    };
    ProgressStyle::with_template(template)
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("##-")
}

/// Rebuild the JSON-Lines subtask list from the currently in-flight
/// byte-oriented components (composefs-rs does not expose object-count
/// progress in a form the `ProgressBytes` schema can represent, so
/// [`ProgressUnit::Items`] components only drive the terminal UI).
fn json_subtasks<'a>(
    active: &'a HashMap<ComponentId, ActiveComponent>,
) -> (Vec<SubTaskBytes<'a>>, u64, u64) {
    let mut bytes_fetched = 0u64;
    let mut bytes_total = 0u64;
    let mut total_known = true;
    let mut subtasks = Vec::new();
    for (id, comp) in active {
        if comp.unit != ProgressUnit::Bytes {
            continue;
        }
        bytes_fetched = bytes_fetched.saturating_add(comp.fetched);
        match comp.total {
            Some(total) => bytes_total = bytes_total.saturating_add(total),
            None => total_known = false,
        }
        let label = short_id(id);
        subtasks.push(SubTaskBytes {
            subtask: "composefs_layer".into(),
            description: format!("Layer: {label}").into(),
            id: id.as_str().into(),
            // Unlike `steps_cached` below, there's no equivalent byte count
            // available here: `ProgressEvent::Skipped` (composefs-rs's signal
            // for an already-present component) carries only a `ComponentId`,
            // not a size, even though callers generally know the size at the
            // point they emit it (e.g. from the OCI manifest descriptor).
            // Until composefs-rs's `Skipped` event carries a `total`, we have
            // no way to attribute cached bytes to a specific subtask.
            bytes_cached: 0,
            bytes: comp.fetched,
            bytes_total: comp.total.unwrap_or(0),
        });
    }
    // `bytes_total == 0` is the protocol's way of saying "unspecified"; only
    // report a real aggregate when every in-flight component's size is known.
    if !total_known {
        bytes_total = 0;
    }
    (subtasks, bytes_fetched, bytes_total)
}

/// Background task consuming [`ProgressEvent`]s and updating both the
/// interactive terminal display and the JSON-Lines progress writer.
async fn drive_progress(
    mut rx: mpsc::UnboundedReceiver<ProgressEvent>,
    quiet: bool,
    prog: ProgressWriter,
) -> ProgressWriter {
    let multi = MultiProgress::new();
    if quiet {
        multi.set_draw_target(ProgressDrawTarget::hidden());
    }

    let mut active: HashMap<ComponentId, ActiveComponent> = HashMap::new();
    // Components actually downloaded this run, versus ones that were already
    // present (`ProgressEvent::Skipped`) and thus required no network I/O.
    // Kept separate to match the `steps`/`steps_cached` convention used by
    // the ostree pull path (see `crate::deploy`): `steps` counts real work
    // done now, `steps_cached` counts work a prior run already did.
    let mut steps_done: u64 = 0;
    let mut steps_cached: u64 = 0;
    // Whether any component has actually started, finished, or been skipped
    // yet. Used instead of `!subtasks.is_empty()` to decide whether to emit
    // a JSON-Lines update: gating on "a `Bytes`-unit component is currently
    // active" would both drop the final update once the last component
    // completes and `active` drains back to empty, and suppress every
    // update during a purely `Items`-unit pull (e.g. a containers-storage
    // zero-copy import), which never populates `subtasks` at all.
    let mut any_activity = false;

    while let Some(event) = rx.recv().await {
        // `Done`/`Skipped` are discrete, one-shot milestones (a component's
        // step count changes exactly once), unlike the continuous `Progress`
        // ticks within a single component's transfer. Send those via the
        // non-lossy `ProgressWriter::send`, matching the convention already
        // used for the equivalent ostree layer-completion event in
        // `crate::deploy` ("Cannot be lossy or it is dropped"): `send_lossy`
        // silently drops updates that land within its refresh window, which
        // would otherwise risk losing the final `steps`/`steps_cached` tally
        // when components complete in a tight burst.
        let mut required = false;

        match event {
            ProgressEvent::Started { id, total, unit } => {
                let bar = if let Some(total) = total {
                    multi.add(ProgressBar::new(total))
                } else {
                    multi.add(ProgressBar::new_spinner())
                };
                bar.set_style(bar_style(unit));
                bar.set_message(short_id(&id));
                active.insert(
                    id,
                    ActiveComponent {
                        unit,
                        fetched: 0,
                        total,
                        bar,
                    },
                );
                any_activity = true;
            }
            ProgressEvent::Progress { id, fetched, total } => {
                if let Some(comp) = active.get_mut(&id) {
                    if let Some(total) = total {
                        comp.bar.set_length(total);
                        comp.total = Some(total);
                    }
                    comp.bar.set_position(fetched);
                    comp.fetched = fetched;
                }
            }
            ProgressEvent::Done { id, transferred } => {
                if let Some(comp) = active.remove(&id) {
                    comp.bar.finish_and_clear();
                    let _ = transferred;
                }
                steps_done = steps_done.saturating_add(1);
                any_activity = true;
                required = true;
            }
            ProgressEvent::Skipped { id } => {
                if let Some(comp) = active.remove(&id) {
                    comp.bar.finish_with_message("skipped");
                }
                steps_cached = steps_cached.saturating_add(1);
                any_activity = true;
                required = true;
            }
            ProgressEvent::Message(msg) => {
                let _ = multi.println(msg);
            }
            // `ProgressEvent` is `#[non_exhaustive]`; ignore future variants
            // rather than failing to compile against newer composefs-rs.
            _ => {}
        }

        let (subtasks, bytes, bytes_total) = json_subtasks(&active);
        let event = Event::ProgressBytes {
            task: "pulling".into(),
            description: "Pulling composefs image".into(),
            id: "composefs-pull".into(),
            // See the comment on `bytes_cached` in `json_subtasks`: unlike
            // `steps_cached`, composefs-rs gives us no way to know how
            // many bytes an already-present (`Skipped`) component would
            // have been, so this can't be anything but 0 for now.
            bytes_cached: 0,
            bytes,
            // Total across all in-flight components is inherently a
            // moving target since composefs-rs does not report an
            // upfront count of components; report 0 ("unspecified")
            // unless every in-flight component has a known size.
            bytes_total,
            steps_cached,
            steps: steps_done,
            steps_total: 0,
            subtasks,
        };
        if required {
            prog.send(event).await;
        } else if any_activity {
            prog.send_lossy(event).await;
        }
    }

    prog
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_component(unit: ProgressUnit, fetched: u64, total: Option<u64>) -> ActiveComponent {
        ActiveComponent {
            unit,
            fetched,
            total,
            bar: ProgressBar::hidden(),
        }
    }

    #[test]
    fn test_short_id_truncates_long_ids() {
        let id: ComponentId =
            "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".into();
        let short = short_id(&id);
        assert_eq!(short.chars().count(), ID_DISPLAY_LEN);
        assert!(id.as_str().starts_with(&short));
    }

    #[test]
    fn test_short_id_passes_through_short_ids() {
        let id: ComponentId = "obj-1".into();
        assert_eq!(short_id(&id), "obj-1");
    }

    #[test]
    fn test_json_subtasks_ignores_items_unit() {
        let mut active = HashMap::new();
        active.insert(
            ComponentId::from("objects"),
            active_component(ProgressUnit::Items, 5, Some(10)),
        );
        let (subtasks, bytes, bytes_total) = json_subtasks(&active);
        assert!(
            subtasks.is_empty(),
            "Items-unit components have no bytes subtask"
        );
        assert_eq!(bytes, 0);
        assert_eq!(bytes_total, 0);
    }

    #[test]
    fn test_json_subtasks_aggregates_known_totals() {
        let mut active = HashMap::new();
        active.insert(
            ComponentId::from("layer-a"),
            active_component(ProgressUnit::Bytes, 100, Some(200)),
        );
        active.insert(
            ComponentId::from("layer-b"),
            active_component(ProgressUnit::Bytes, 50, Some(300)),
        );
        let (subtasks, bytes, bytes_total) = json_subtasks(&active);
        assert_eq!(subtasks.len(), 2);
        assert_eq!(bytes, 150);
        assert_eq!(bytes_total, 500);
    }

    #[test]
    fn test_json_subtasks_unknown_total_is_unspecified() {
        let mut active = HashMap::new();
        active.insert(
            ComponentId::from("layer-a"),
            active_component(ProgressUnit::Bytes, 100, Some(200)),
        );
        active.insert(
            ComponentId::from("layer-b"),
            // Total isn't known yet for this component.
            active_component(ProgressUnit::Bytes, 10, None),
        );
        let (subtasks, bytes, bytes_total) = json_subtasks(&active);
        assert_eq!(subtasks.len(), 2);
        assert_eq!(bytes, 110);
        // Since one component's total is unknown, the aggregate must be
        // reported as unspecified (0) rather than an understated value.
        assert_eq!(bytes_total, 0);
    }

    #[tokio::test]
    async fn test_drive_progress_runs_to_completion_on_channel_close() {
        let (reporter, handle) = spawn(true, ProgressWriter::default());
        reporter.report(ProgressEvent::Started {
            id: "layer-a".into(),
            total: Some(100),
            unit: ProgressUnit::Bytes,
        });
        reporter.report(ProgressEvent::Progress {
            id: "layer-a".into(),
            fetched: 100,
            total: Some(100),
        });
        reporter.report(ProgressEvent::Done {
            id: "layer-a".into(),
            transferred: 100,
        });
        reporter.report(ProgressEvent::Message("done".into()));
        // Dropping the reporter closes the channel, letting the task exit.
        drop(reporter);
        handle.await.expect("progress task should not panic");
    }

    /// Reads every `ProgressBytes` event from a [`ProgressWriter`] pipe until
    /// EOF, returning `(steps, steps_cached, subtasks.len())` for each one in
    /// the order received.
    async fn collect_progress_bytes(
        recv: tokio::net::unix::pipe::Receiver,
    ) -> Vec<(u64, u64, usize)> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let mut lines = BufReader::new(recv).lines();
        let mut events = Vec::new();
        while let Some(line) = lines.next_line().await.expect("read line") {
            if let Ok(crate::progress_jsonl::Event::ProgressBytes {
                steps,
                steps_cached,
                subtasks,
                ..
            }) = serde_json::from_str(&line)
            {
                events.push((steps, steps_cached, subtasks.len()));
            }
        }
        events
    }

    /// `Done` (actually downloaded) and `Skipped` (already present) events
    /// must be tallied into `steps`/`steps_cached` separately rather than a
    /// single shared counter, matching the convention used by the ostree
    /// pull path (`crate::deploy`). Both are sent via the non-lossy
    /// `ProgressWriter::send`, so no delay is needed between them to dodge
    /// `send_lossy`'s rate limiting.
    #[tokio::test]
    async fn test_drive_progress_reports_steps_cached_separately() {
        let (send, recv) = tokio::net::unix::pipe::pipe().expect("create pipe");
        let prog: ProgressWriter = send.try_into().expect("ProgressWriter from pipe");
        let (reporter, handle) = spawn(true, prog);

        reporter.report(ProgressEvent::Started {
            id: "layer-fetched".into(),
            total: Some(100),
            unit: ProgressUnit::Bytes,
        });
        reporter.report(ProgressEvent::Done {
            id: "layer-fetched".into(),
            transferred: 100,
        });
        reporter.report(ProgressEvent::Skipped {
            id: "layer-cached".into(),
        });
        drop(reporter);
        handle.await.expect("progress task should not panic");

        // The last event reflects the final tally: one component was
        // actually fetched (Done) and one was already cached (Skipped).
        let events = collect_progress_bytes(recv).await;
        let &(steps, steps_cached, _) = events.last().expect("at least one event observed");
        assert_eq!(steps, 1, "one component was actually downloaded");
        assert_eq!(steps_cached, 1, "one component was already cached");
    }

    /// Once the last in-flight component finishes, `active` drains back to
    /// empty and `json_subtasks` has nothing left to report — but the final
    /// `steps`/`steps_cached` tally must still be flushed rather than
    /// silently dropped just because there's no `Bytes`-unit subtask left to
    /// show alongside it.
    #[tokio::test]
    async fn test_drive_progress_flushes_final_event_after_last_component_finishes() {
        let (send, recv) = tokio::net::unix::pipe::pipe().expect("create pipe");
        let prog: ProgressWriter = send.try_into().expect("ProgressWriter from pipe");
        let (reporter, handle) = spawn(true, prog);

        reporter.report(ProgressEvent::Started {
            id: "layer-a".into(),
            total: Some(100),
            unit: ProgressUnit::Bytes,
        });
        reporter.report(ProgressEvent::Done {
            id: "layer-a".into(),
            transferred: 100,
        });
        drop(reporter);
        handle.await.expect("progress task should not panic");

        let events = collect_progress_bytes(recv).await;
        let &(steps, _, subtasks_len) = events.last().expect("at least one event observed");
        assert_eq!(steps, 1, "the completed component must still be counted");
        assert_eq!(
            subtasks_len, 0,
            "no components remain in flight to report as subtasks"
        );
    }

    /// A pull consisting solely of [`ProgressUnit::Items`] components (e.g. a
    /// containers-storage zero-copy import) never populates `json_subtasks`,
    /// since that unit has no `SubTaskBytes` representation. Progress must
    /// still be reported at the aggregate `steps`/`steps_cached` level rather
    /// than emitting nothing at all for the whole pull.
    #[tokio::test]
    async fn test_drive_progress_reports_steps_for_items_only_pull() {
        let (send, recv) = tokio::net::unix::pipe::pipe().expect("create pipe");
        let prog: ProgressWriter = send.try_into().expect("ProgressWriter from pipe");
        let (reporter, handle) = spawn(true, prog);

        reporter.report(ProgressEvent::Started {
            id: "objects".into(),
            total: Some(10),
            unit: ProgressUnit::Items,
        });
        reporter.report(ProgressEvent::Done {
            id: "objects".into(),
            transferred: 10,
        });
        drop(reporter);
        handle.await.expect("progress task should not panic");

        let events = collect_progress_bytes(recv).await;
        let &(steps, _, _) = events
            .last()
            .expect("an Items-only pull must still emit progress events");
        assert_eq!(steps, 1);
    }
}
