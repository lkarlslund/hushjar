//! Timing rules for live updates, as plain values so they can be tested
//! without threads or a clock: when to sync after the server says the vault
//! changed, and when a failing notification connection is worth mentioning.

use std::time::{Duration, Instant};

/// How long the server must stay quiet before we sync.
pub const QUIET: Duration = Duration::from_secs(2);
/// The longest a steady stream of changes can delay the sync.
pub const LONGEST: Duration = Duration::from_secs(10);
/// How often the worker looks at the notification connection.
pub const WATCH_EVERY: Duration = Duration::from_secs(15);
/// Failed looks in a row before the problem is shown to the user.
const FAILED_LOOKS: u32 = 3;

/// Collects "the vault changed" messages into one sync. Each message pushes
/// the sync back by [`QUIET`], but never past [`LONGEST`] after the first.
#[derive(Debug, Default)]
pub struct Debounce {
    first: Option<Instant>,
    deadline: Option<Instant>,
}

impl Debounce {
    /// Records a change message received at `now`.
    pub fn note(&mut self, now: Instant) {
        let first = *self.first.get_or_insert(now);
        self.deadline = Some((now + QUIET).min(first + LONGEST));
    }

    /// When the sync is due, if a change is waiting.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// True once the sync is due. Call [`Debounce::clear`] when it starts.
    pub fn due(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Decides when a failing notification connection is reported: only after
/// several looks in a row found it down with a reason, and again when it
/// comes back. A single dropped connection that reconnects stays unseen.
#[derive(Debug, Default)]
pub struct Watch {
    failed: u32,
    reported: bool,
}

impl Watch {
    /// Feeds one look at the listener. Returns `Some(status)` when the status
    /// shown to the user should change: `Some(Some(reason))` to show a
    /// problem, `Some(None)` to clear it.
    pub fn look(&mut self, connected: bool, problem: Option<String>) -> Option<Option<String>> {
        if connected || problem.is_none() {
            // Still starting up (no reason yet) counts as neither.
            if connected {
                self.failed = 0;
            }
            return (connected && std::mem::take(&mut self.reported)).then_some(None);
        }
        self.failed += 1;
        if self.failed >= FAILED_LOOKS && !self.reported {
            self.reported = true;
            return Some(problem);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn debounce_waits_for_quiet() {
        let t = Instant::now();
        let mut d = Debounce::default();
        assert_eq!(d.deadline(), None);
        assert!(!d.due(t));
        d.note(t);
        assert_eq!(d.deadline(), Some(t + QUIET));
        assert!(!d.due(t + secs(1)));
        d.note(t + secs(1));
        assert_eq!(d.deadline(), Some(t + secs(1) + QUIET));
        assert!(!d.due(t + secs(2)));
        assert!(d.due(t + secs(3)));
    }

    #[test]
    fn debounce_never_waits_past_the_longest() {
        let t = Instant::now();
        let mut d = Debounce::default();
        for i in 0..20 {
            d.note(t + secs(i));
        }
        assert_eq!(d.deadline(), Some(t + LONGEST));
        assert!(d.due(t + LONGEST));
    }

    #[test]
    fn debounce_starts_over_after_clear() {
        let t = Instant::now();
        let mut d = Debounce::default();
        d.note(t);
        d.clear();
        assert_eq!(d.deadline(), None);
        d.note(t + secs(60));
        assert_eq!(d.deadline(), Some(t + secs(60) + QUIET));
    }

    #[test]
    fn watch_reports_only_repeated_failures() {
        let mut w = Watch::default();
        let bad = || Some("refused".to_string());
        assert_eq!(w.look(false, bad()), None);
        assert_eq!(w.look(false, bad()), None);
        assert_eq!(w.look(false, bad()), Some(bad()));
        // Reported once, not on every look.
        assert_eq!(w.look(false, bad()), None);
        assert_eq!(w.look(true, None), Some(None));
        assert_eq!(w.look(true, None), None);
    }

    #[test]
    fn watch_forgets_a_recovered_connection() {
        let mut w = Watch::default();
        let bad = || Some("refused".to_string());
        w.look(false, bad());
        w.look(false, bad());
        assert_eq!(w.look(true, None), None);
        assert_eq!(w.look(false, bad()), None);
        assert_eq!(w.look(false, bad()), None);
        assert_eq!(w.look(false, bad()), Some(bad()));
    }

    #[test]
    fn watch_ignores_a_listener_that_is_still_starting() {
        let mut w = Watch::default();
        for _ in 0..10 {
            assert_eq!(w.look(false, None), None);
        }
    }
}
