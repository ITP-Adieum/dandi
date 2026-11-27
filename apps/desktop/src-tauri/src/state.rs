use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dandi_core::CancellationToken;

/// Tracks active cancellable archive operations and startup/OS-opened file paths.
#[derive(Default)]
pub struct AppState {
    operations: Arc<Mutex<HashMap<String, CancellationToken>>>,
    pending_open_paths: Mutex<Vec<String>>,
    frontend_ready: AtomicBool,
}

/// RAII guard that removes an operation's cancellation handle when the task ends.
pub struct OperationGuard {
    op_id: String,
    operations: Arc<Mutex<HashMap<String, CancellationToken>>>,
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut guard = match self.operations.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.remove(&self.op_id);
    }
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a new active operation and returns its `CancellationToken` + RAII cleanup guard.
    pub fn register_operation(&self, op_id: String) -> (CancellationToken, OperationGuard) {
        let token = CancellationToken::new();
        {
            let mut guard = match self.operations.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.insert(op_id.clone(), token.clone());
        }
        let guard = OperationGuard {
            op_id,
            operations: Arc::clone(&self.operations),
        };
        (token, guard)
    }

    /// Cancels an active operation by ID. Returns `true` if a matching active operation existed.
    pub fn cancel_operation(&self, op_id: &str) -> bool {
        let token = {
            let guard = match self.operations.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.get(op_id).cloned()
        };
        if let Some(tok) = token {
            tok.cancel();
            true
        } else {
            false
        }
    }

    /// Returns the number of currently active operations (used in tests/diagnostics).
    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        let guard = match self.operations.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.len()
    }

    /// Returns whether the frontend has registered its event listener and drained startup paths.
    #[cfg(test)]
    pub fn is_frontend_ready(&self) -> bool {
        self.frontend_ready.load(Ordering::SeqCst)
    }

    /// Queues startup/OS-opened paths while the frontend is not yet ready.
    ///
    /// Synchronized on `pending_open_paths` with `take_pending_open_paths` so a path is
    /// guaranteed to be delivered either via the drained queue OR via a live event — never
    /// dropped and never delivered twice.
    ///
    /// Returns `true` if the frontend is already ready (caller should emit the live event),
    /// or `false` if the paths were queued for startup drain (caller must not emit).
    pub fn enqueue_or_should_emit(&self, paths: Vec<String>) -> bool {
        if paths.is_empty() {
            return false;
        }
        let mut guard = match self.pending_open_paths.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.frontend_ready.load(Ordering::SeqCst) {
            true
        } else {
            guard.extend(paths);
            false
        }
    }

    /// Marks the frontend ready and atomically drains all queued OS-opened paths.
    pub fn take_pending_open_paths(&self) -> Vec<String> {
        let mut guard = match self.pending_open_paths.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.frontend_ready.store(true, Ordering::SeqCst);
        std::mem::take(&mut *guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_registration_cancellation_and_raii_cleanup() {
        let state = AppState::new();
        assert_eq!(state.active_count(), 0);
        assert!(!state.cancel_operation("nonexistent"));

        let (token, guard) = state.register_operation("op-1".to_string());
        assert_eq!(state.active_count(), 1);
        assert!(!token.is_cancelled());

        assert!(state.cancel_operation("op-1"));
        assert!(token.is_cancelled());

        // Cancelling twice stays safe and idempotent while still registered.
        assert!(state.cancel_operation("op-1"));

        drop(guard);
        assert_eq!(state.active_count(), 0);
        assert!(!state.cancel_operation("op-1"));
    }

    #[test]
    fn frontend_ready_gating_prevents_duplicate_delivery() {
        let state = AppState::new();
        assert!(!state.is_frontend_ready());

        // Before frontend is ready, incoming paths are queued and NOT emitted.
        assert!(!state.enqueue_or_should_emit(vec!["/tmp/a.zip".into()]));
        assert!(!state.enqueue_or_should_emit(vec!["/tmp/b.7z".into()]));

        // Draining flips frontend_ready to true and returns queued paths once.
        let drained = state.take_pending_open_paths();
        assert!(state.is_frontend_ready());
        assert_eq!(drained, vec!["/tmp/a.zip", "/tmp/b.7z"]);
        assert!(state.take_pending_open_paths().is_empty());

        // After frontend is ready, incoming paths signal live emit and are NOT queued.
        assert!(state.enqueue_or_should_emit(vec!["/tmp/c.zip".into()]));
        assert!(state.take_pending_open_paths().is_empty());
    }
}
