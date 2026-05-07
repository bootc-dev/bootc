//! Helpers for bridging GLib async/mainloop with Tokio.

use anyhow::Result;
use core::fmt::{Debug, Display};
use futures_util::{Future, FutureExt};
use ostree::gio;
use ostree::prelude::{CancellableExt, CancellableExtManual};

/// Call a faillible future, while monitoring `cancellable` and return an error if cancelled.
pub async fn run_with_cancellable<F, R>(f: F, cancellable: &gio::Cancellable) -> Result<R>
where
    F: Future<Output = Result<R>>,
{
    // Bridge GCancellable to a tokio notification
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let notify2 = notify.clone();
    cancellable.connect_cancelled(move |_| notify2.notify_one());
    cancellable.set_error_if_cancelled()?;
    // See https://blog.yoshuawuyts.com/futures-concurrency-3/ on why
    // `select!` is a trap in general, but I believe this case is safe.
    tokio::select! {
       r = f => r,
       _ = notify.notified() => {
           Err(anyhow::anyhow!("Operation was cancelled"))
       }
    }
}

struct CancelOnDrop(gio::Cancellable);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Wrapper for [`tokio::task::spawn_blocking`] which provides a [`gio::Cancellable`] that will be triggered on drop.
///
/// This function should be used in a Rust/tokio native `async fn`, but that want to invoke
/// GLib style blocking APIs that use `GCancellable`.  The cancellable will be triggered when this
/// future is dropped, which helps bound thread usage.
///
/// This is in a sense the inverse of [`run_with_cancellable`].
pub fn spawn_blocking_cancellable<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce(&gio::Cancellable) -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let dropper = CancelOnDrop(gio::Cancellable::new());
        f(&dropper.0)
    })
}

/// Flatten a nested `Result<Result<T>>`, defaulting to converting the error type to an `anyhow::Error`.
/// See <https://doc.rust-lang.org/std/result/enum.Result.html#method.flatten>
pub(crate) fn flatten_anyhow<T, E>(r: std::result::Result<Result<T>, E>) -> Result<T>
where
    E: Display + Debug + Send + Sync + 'static,
{
    match r {
        Ok(x) => x,
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

/// A wrapper around [`spawn_blocking_cancellable`] that flattens nested results.
pub fn spawn_blocking_cancellable_flatten<F, T>(f: F) -> impl Future<Output = Result<T>>
where
    F: FnOnce(&gio::Cancellable) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking_cancellable(f).map(flatten_anyhow)
}

/// A wrapper around [`tokio::task::spawn_blocking`] that flattens nested results.
pub fn spawn_blocking_flatten<F, T>(f: F) -> impl Future<Output = Result<T>>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f).map(flatten_anyhow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cancellable() {
        let cancellable = ostree::gio::Cancellable::new();

        let cancellable_copy = cancellable.clone();
        let s = async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            cancellable_copy.cancel();
        };
        let r = async move {
            tokio::time::sleep(std::time::Duration::from_secs(200)).await;
            Ok(())
        };
        let r = run_with_cancellable(r, &cancellable);
        let (_, r) = tokio::join!(s, r);
        assert!(r.is_err());
    }
}
