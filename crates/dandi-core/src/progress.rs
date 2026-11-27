use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{DandiError, Result};

/// Cooperative cancellation handle shared between caller and engine loops.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(DandiError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressPhase {
    Scanning,
    Packing,
    Unpacking,
    Repacking,
    Finalizing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub phase: ProgressPhase,
    pub current_entry: String,
    pub entries_done: usize,
    pub entries_total: usize,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

/// Sink for streaming progress updates from `dandi-core` to CLI/GUI callers.
pub trait ProgressObserver: Send + Sync {
    fn on_progress(&self, event: &ProgressEvent);
}

/// Default observer that discards progress events.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopProgressObserver;

impl ProgressObserver for NoopProgressObserver {
    fn on_progress(&self, _event: &ProgressEvent) {}
}

/// Wraps an inner observer and rate-limits non-terminal progress callbacks.
pub struct ThrottledProgressObserver<F> {
    interval: Duration,
    last_emit: Mutex<Option<Instant>>,
    callback: F,
}

impl<F> ThrottledProgressObserver<F>
where
    F: Fn(&ProgressEvent) + Send + Sync,
{
    pub fn new(interval: Duration, callback: F) -> Self {
        Self {
            interval,
            last_emit: Mutex::new(None),
            callback,
        }
    }
}

impl<F> ProgressObserver for ThrottledProgressObserver<F>
where
    F: Fn(&ProgressEvent) + Send + Sync,
{
    fn on_progress(&self, event: &ProgressEvent) {
        let is_terminal = event.phase == ProgressPhase::Finalizing
            || (event.entries_total > 0 && event.entries_done >= event.entries_total);
        let should_emit = match self.last_emit.lock() {
            Ok(mut guard) => {
                let now = Instant::now();
                let elapsed_ok = guard
                    .map(|prev| now.duration_since(prev) >= self.interval)
                    .unwrap_or(true);
                if is_terminal || elapsed_ok {
                    *guard = Some(now);
                    true
                } else {
                    false
                }
            }
            Err(_) => is_terminal,
        };
        if should_emit {
            (self.callback)(event);
        }
    }
}
