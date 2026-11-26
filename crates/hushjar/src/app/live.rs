//! Live updates and organisation policies as the app sees them: what the
//! account worker reports about the server, and the rules that follow from
//! the policies it sends. Rules are plain functions over [`Policies`] so they
//! can be tested without a window.

use hushjar_core::policy::{Policies, TimeoutAction, VaultTimeoutPolicy};
use hushjar_core::vault::Collection;

use super::*;

/// The shortest idle time the app can enforce when a policy says "lock
/// immediately": the idle check runs once a second, and a timeout of nothing
/// would lock the vault under the user's hands.
const IMMEDIATE: Duration = Duration::from_secs(60);

/// The policies of an account, once a sync has told us. `None` until then.
pub(super) fn policies(state: &State, account: usize) -> Option<&Policies> {
    state.accounts.get(account)?.policies.as_ref()
}

/// Whether an organisation forbids unlocking this account with a PIN. Read by
/// the PIN settings and the unlock screen.
pub(super) fn pin_disabled(state: &State, account: usize) -> bool {
    policies(state, account).is_some_and(|p| p.pin_unlock_disabled)
}

/// The longest idle time the vault-timeout policies allow, over all of them,
/// and the action they force. Log out wins over lock.
pub(super) fn strictest_timeout<'a>(
    policies: impl IntoIterator<Item = &'a VaultTimeoutPolicy>,
) -> (Option<Duration>, Option<TimeoutAction>) {
    let mut limit: Option<Duration> = None;
    let mut action = None;
    for p in policies {
        let this = if p.immediately {
            Some(IMMEDIATE)
        } else {
            p.max_minutes
                .map(|m| Duration::from_secs(u64::from(m) * 60))
        };
        limit = match (limit, this) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        action = match (action, p.action) {
            (Some(TimeoutAction::LogOut), _) | (_, Some(TimeoutAction::LogOut)) => {
                Some(TimeoutAction::LogOut)
            }
            (a, b) => a.or(b),
        };
    }
    (limit, action)
}

/// What to do when the idle time runs out: the policy's action when it
/// forces one, otherwise the user's choice.
pub(super) fn effective_action(user: LockAction, forced: Option<TimeoutAction>) -> LockAction {
    match forced {
        Some(TimeoutAction::LogOut) => LockAction::LogOut,
        Some(TimeoutAction::Lock) => LockAction::Lock,
        None => user,
    }
}

/// Where a new item goes when personal items are not allowed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Ownership {
    /// Nothing to change.
    AsChosen,
    /// Create it in this collection of this organisation.
    Collection { organization: String, id: String },
    /// There is no collection the user can add to.
    NoCollection,
}

/// Applies the "no personal items" policy to a new item that has no
/// organisation: picks the first collection the user can edit.
pub(super) fn ownership(
    policies: Option<&Policies>,
    has_organization: bool,
    collections: &[Collection],
) -> Ownership {
    if has_organization || !policies.is_some_and(|p| p.personal_ownership_disabled) {
        return Ownership::AsChosen;
    }
    match collections.iter().find(|c| !c.read_only) {
        Some(c) => Ownership::Collection {
            organization: c.organization_id.clone(),
            id: c.id.clone(),
        },
        None => Ownership::NoCollection,
    }
}

/// The sentence in the settings that explains the policy's time limit.
pub(super) fn timeout_note(limit: Duration) -> String {
    let minutes = limit.as_secs() / 60;
    match minutes {
        0 | 1 => "An organisation policy locks accounts after at most 1 minute.".into(),
        n => format!("An organisation policy locks accounts after at most {n} minutes."),
    }
}

impl State {
    /// The vault-timeout policies of the unlocked accounts.
    fn timeout_policies(&self) -> impl Iterator<Item = &VaultTimeoutPolicy> {
        self.accounts
            .iter()
            .filter(|a| a.vault.is_some())
            .filter_map(|a| a.policies.as_ref()?.vault_timeout.as_ref())
    }

    /// The longest idle time organisation policies allow, if any.
    pub(super) fn policy_idle_limit(&self) -> Option<Duration> {
        strictest_timeout(self.timeout_policies()).0
    }

    /// What happens at timeout, after any organisation policy.
    pub(super) fn timeout_action(&self) -> LockAction {
        effective_action(
            self.prefs.lock_action,
            strictest_timeout(self.timeout_policies()).1,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeout(minutes: Option<u32>, action: Option<TimeoutAction>) -> VaultTimeoutPolicy {
        VaultTimeoutPolicy {
            max_minutes: minutes,
            action,
            ..VaultTimeoutPolicy::default()
        }
    }

    fn collection(id: &str, read_only: bool) -> Collection {
        Collection {
            id: id.into(),
            organization_id: "org".into(),
            name: id.into(),
            read_only,
        }
    }

    #[test]
    fn no_timeout_policy_means_no_limit() {
        assert_eq!(strictest_timeout([]), (None, None));
        // A policy that only asks for the system lock sets no timer.
        let only_lock = VaultTimeoutPolicy {
            on_system_lock: true,
            ..VaultTimeoutPolicy::default()
        };
        assert_eq!(strictest_timeout([&only_lock]), (None, None));
    }

    #[test]
    fn the_shortest_timeout_wins() {
        let (a, b) = (timeout(Some(30), None), timeout(Some(10), None));
        assert_eq!(
            strictest_timeout([&a, &b]).0,
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn immediately_beats_minutes() {
        let now = VaultTimeoutPolicy {
            immediately: true,
            ..VaultTimeoutPolicy::default()
        };
        let later = timeout(Some(120), None);
        assert_eq!(strictest_timeout([&later, &now]).0, Some(IMMEDIATE));
    }

    #[test]
    fn log_out_wins_over_lock() {
        let lock = timeout(None, Some(TimeoutAction::Lock));
        let out = timeout(None, Some(TimeoutAction::LogOut));
        assert_eq!(
            strictest_timeout([&lock, &out]).1,
            Some(TimeoutAction::LogOut)
        );
        assert_eq!(
            strictest_timeout([&out, &lock]).1,
            Some(TimeoutAction::LogOut)
        );
        assert_eq!(strictest_timeout([&lock]).1, Some(TimeoutAction::Lock));
    }

    #[test]
    fn a_forced_action_overrides_the_users_choice() {
        assert_eq!(
            effective_action(LockAction::Lock, Some(TimeoutAction::LogOut)),
            LockAction::LogOut
        );
        assert_eq!(
            effective_action(LockAction::LogOut, Some(TimeoutAction::Lock)),
            LockAction::Lock
        );
        assert_eq!(
            effective_action(LockAction::LogOut, None),
            LockAction::LogOut
        );
    }

    #[test]
    fn personal_items_are_left_alone_without_the_policy() {
        let c = [collection("a", false)];
        assert_eq!(ownership(None, false, &c), Ownership::AsChosen);
        let open = Policies::default();
        assert_eq!(ownership(Some(&open), false, &c), Ownership::AsChosen);
    }

    #[test]
    fn the_policy_picks_the_first_editable_collection() {
        let strict = Policies {
            personal_ownership_disabled: true,
            ..Policies::default()
        };
        let c = [collection("view", true), collection("edit", false)];
        assert_eq!(
            ownership(Some(&strict), false, &c),
            Ownership::Collection {
                organization: "org".into(),
                id: "edit".into()
            }
        );
        assert_eq!(
            ownership(Some(&strict), false, &c[..1]),
            Ownership::NoCollection
        );
        // Already in an organisation: nothing to do.
        assert_eq!(ownership(Some(&strict), true, &c[..1]), Ownership::AsChosen);
    }

    #[test]
    fn the_timeout_note_reads_naturally() {
        assert!(timeout_note(Duration::from_secs(60)).contains("1 minute."));
        assert!(timeout_note(Duration::from_secs(900)).contains("15 minutes"));
    }
}
