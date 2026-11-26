//! Organisation policies that change what the client allows.
//!
//! `/api/sync` lists the policies of the user's organisations in `policies`
//! (`type`, `enabled`, `data`, `organizationId`) and the user's memberships
//! in `profile.organizations` (`type` = role, `status`, `enabled`,
//! `usePolicies`). [`Policies::from_sync`] works out which policies apply to
//! this user and folds them into one summary, taking the strictest value
//! when several organisations set the same policy.
//!
//! Which policies apply follows Bitwarden's SDK (`bitwarden-policies`,
//! `PolicyDefinition` and `PolicyView::into_enforced`), which the clients use
//! since the move away from `DefaultPolicyService.isExemptFromPolicy`:
//!
//! - the policy is enabled, and for the user's membership (when the profile
//!   lists one): the organisation is enabled, uses policies, the user has
//!   accepted or been confirmed, is not exempt by role, and is not a provider
//!   user;
//! - owners and admins are exempt by default; the maximum vault timeout
//!   exempts only owners; the master password, password generator, remove
//!   unlock with PIN and restricted item types policies exempt no one.
//!
//! Policy numbers are Bitwarden's `PolicyType` (`policy_type.rs` in the SDK).

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;

use crate::api::{field, field_str};

/// Bitwarden's policy type numbers.
pub mod kind {
    pub const TWO_FACTOR_AUTHENTICATION: u8 = 0;
    pub const MASTER_PASSWORD: u8 = 1;
    pub const PASSWORD_GENERATOR: u8 = 2;
    pub const SINGLE_ORG: u8 = 3;
    pub const REQUIRE_SSO: u8 = 4;
    /// Called "personal ownership" in older clients and Vaultwarden.
    pub const ORGANIZATION_DATA_OWNERSHIP: u8 = 5;
    pub const DISABLE_SEND: u8 = 6;
    pub const SEND_OPTIONS: u8 = 7;
    pub const RESET_PASSWORD: u8 = 8;
    pub const MAXIMUM_VAULT_TIMEOUT: u8 = 9;
    pub const DISABLE_PERSONAL_VAULT_EXPORT: u8 = 10;
    pub const ACTIVATE_AUTOFILL: u8 = 11;
    pub const AUTOMATIC_APP_LOG_IN: u8 = 12;
    pub const FREE_FAMILIES_SPONSORSHIP: u8 = 13;
    pub const REMOVE_UNLOCK_WITH_PIN: u8 = 14;
    pub const RESTRICTED_ITEM_TYPES: u8 = 15;
    pub const URI_MATCH_DEFAULTS: u8 = 16;
    pub const AUTOTYPE_DEFAULT_SETTING: u8 = 17;
    pub const AUTOMATIC_USER_CONFIRMATION: u8 = 18;
    pub const BLOCK_CLAIMED_DOMAIN_ACCOUNT_CREATION: u8 = 19;
    pub const ORGANIZATION_USER_NOTIFICATION: u8 = 20;
    /// The newer combined Send policy (disable Send, hide email and more).
    pub const SEND_CONTROLS: u8 = 21;
}

/// Membership roles (`OrganizationUserType`).
const OWNER: i64 = 0;
const ADMIN: i64 = 1;
const USER: i64 = 2;
/// Membership statuses (`OrganizationUserStatusType`).
const ACCEPTED: i64 = 1;
const CONFIRMED: i64 = 2;

/// Item type number for cards, which the restricted item types policy blocks
/// when it carries no list.
const CARD: u8 = 3;

/// Which generator the organisation forces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratorType {
    Password,
    Passphrase,
}

/// Password generator minimums (policy 2). Every value is a floor: the
/// generator may go above a minimum or switch on more character sets, never
/// below or off.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GeneratorPolicy {
    /// Only this generator may be used; `None` leaves the choice open.
    pub forced_type: Option<GeneratorType>,
    pub min_length: u32,
    pub use_upper: bool,
    pub use_lower: bool,
    pub use_numbers: bool,
    pub use_special: bool,
    pub min_numbers: u32,
    pub min_special: u32,
    /// Passphrase: fewest words.
    pub min_words: u32,
    /// Passphrase: capitalise words.
    pub capitalize: bool,
    /// Passphrase: include a number.
    pub include_number: bool,
}

/// What happens when the vault times out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutAction {
    Lock,
    LogOut,
}

/// Limits on the vault timeout (policy 9). The user's own setting must meet
/// every limit that is set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultTimeoutPolicy {
    /// Lock straight away (Bitwarden's "immediately").
    pub immediately: bool,
    /// The longest allowed time before locking, in minutes.
    pub max_minutes: Option<u32>,
    /// Lock at the latest when the computer locks.
    pub on_system_lock: bool,
    /// Lock at the latest when the app restarts.
    pub on_app_restart: bool,
    /// The forced timeout action, if any. Log out wins over lock.
    pub action: Option<TimeoutAction>,
}

/// Master password requirements (policy 1), checked when the password is
/// set or, with `enforce_on_login`, at sign-in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MasterPasswordPolicy {
    /// zxcvbn score, 0 to 4.
    pub min_complexity: u32,
    pub min_length: u32,
    pub require_upper: bool,
    pub require_lower: bool,
    pub require_numbers: bool,
    pub require_special: bool,
    pub enforce_on_login: bool,
}

/// An item type that may not be created or shown (policy 15), except for
/// items owned by the listed organisations, whose policies allow it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestrictedItemType {
    /// The item type number (1 login, 2 note, 3 card, 4 identity, 5 SSH key).
    pub item_type: u8,
    pub allowed_in: Vec<String>,
}

/// The policies that apply to the signed-in user, combined over all of the
/// user's organisations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policies {
    pub generator: Option<GeneratorPolicy>,
    pub vault_timeout: Option<VaultTimeoutPolicy>,
    pub master_password: Option<MasterPasswordPolicy>,
    /// New items must be saved to an organisation, not the personal vault
    /// (policy 5, "remove individual vault").
    pub personal_ownership_disabled: bool,
    /// Sends may not be created or edited (policy 6, or Send controls).
    pub send_disabled: bool,
    /// Sends may not hide the sender's email (policy 7, or Send controls).
    pub send_hide_email_disabled: bool,
    /// The personal vault may not be exported (policy 10).
    pub personal_export_disabled: bool,
    /// Unlocking with a PIN is not allowed (policy 14).
    pub pin_unlock_disabled: bool,
    pub restricted_item_types: Vec<RestrictedItemType>,
    /// Every policy type that applies, with the organisations enforcing it,
    /// for anything not summarised above.
    pub enforced: BTreeMap<u8, Vec<String>>,
}

/// One organisation membership, as far as policies care.
struct Membership {
    role: i64,
    status: i64,
    enabled: bool,
    use_policies: bool,
    provider: bool,
}

/// One policy from the sync.
struct Policy {
    kind: u8,
    organization: String,
    data: Value,
}

impl Policies {
    /// Reads the policies that apply to the user from a `/api/sync` reply.
    pub fn from_sync(sync: &Value) -> Policies {
        let memberships = memberships(sync);
        let enforced: Vec<Policy> = field(sync, "policies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(read_policy)
            .filter(|p| applies(p, memberships.get(&p.organization)))
            .collect();
        let mut policies = Policies::default();
        for policy in &enforced {
            policies
                .enforced
                .entry(policy.kind)
                .or_default()
                .push(policy.organization.clone());
            policies.add(policy);
        }
        policies.restricted_item_types = restricted_item_types(&enforced, &memberships);
        policies
    }

    /// Whether a policy type applies to the user at all.
    pub fn applies(&self, kind: u8) -> bool {
        self.enforced.contains_key(&kind)
    }

    fn add(&mut self, policy: &Policy) {
        let data = &policy.data;
        match policy.kind {
            kind::PASSWORD_GENERATOR => {
                merge_generator(self.generator.get_or_insert_with(Default::default), data)
            }
            kind::MAXIMUM_VAULT_TIMEOUT => merge_timeout(
                self.vault_timeout.get_or_insert_with(Default::default),
                data,
            ),
            kind::MASTER_PASSWORD => merge_master_password(
                self.master_password.get_or_insert_with(Default::default),
                data,
            ),
            kind::ORGANIZATION_DATA_OWNERSHIP => self.personal_ownership_disabled = true,
            kind::DISABLE_SEND => self.send_disabled = true,
            kind::SEND_OPTIONS => self.send_hide_email_disabled |= flag(data, "disableHideEmail"),
            kind::SEND_CONTROLS => {
                self.send_disabled |= flag(data, "disableSend");
                self.send_hide_email_disabled |= flag(data, "disableHideEmail");
            }
            kind::DISABLE_PERSONAL_VAULT_EXPORT => self.personal_export_disabled = true,
            kind::REMOVE_UNLOCK_WITH_PIN => self.pin_unlock_disabled = true,
            _ => {}
        }
    }
}

/// The user's memberships by organisation ID. Organisations reached only
/// through a provider count as provider memberships.
fn memberships(sync: &Value) -> HashMap<String, Membership> {
    let profile = field(sync, "profile");
    let list = |name: &str| {
        profile
            .and_then(|p| field(p, name))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
    };
    let mut found = HashMap::new();
    for org in list("organizations") {
        if let Some(id) = field_str(org, "id") {
            found.insert(id.to_string(), read_membership(org, false));
        }
    }
    for org in list("providerOrganizations") {
        if let Some(id) = field_str(org, "id") {
            found
                .entry(id.to_string())
                .or_insert_with(|| read_membership(org, true));
        }
    }
    found
}

fn read_membership(org: &Value, through_provider: bool) -> Membership {
    let boolean = |name: &str| field(org, name).and_then(Value::as_bool);
    Membership {
        role: number(org, "type").unwrap_or(USER),
        status: number(org, "status").unwrap_or(CONFIRMED),
        enabled: boolean("enabled").unwrap_or(true),
        // A server that sends policies but not this flag is taken to use them.
        use_policies: boolean("usePolicies").unwrap_or(true),
        provider: through_provider || boolean("isProviderUser").unwrap_or(false),
    }
}

/// Reads an enabled policy; disabled and unreadable ones are dropped.
fn read_policy(raw: &Value) -> Option<Policy> {
    if field(raw, "enabled").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let kind = u8::try_from(number(raw, "type")?).ok()?;
    let organization = field_str(raw, "organizationId")?.to_string();
    // Data is an object, but some servers send it as a JSON string.
    let data = match field(raw, "data") {
        Some(Value::String(text)) => serde_json::from_str(text).unwrap_or(Value::Null),
        Some(other) => other.clone(),
        None => Value::Null,
    };
    Some(Policy {
        kind,
        organization,
        data,
    })
}

/// Whether an enabled policy binds this user, per Bitwarden's SDK. A policy
/// for an organisation the profile does not list is enforced, as there.
fn applies(policy: &Policy, membership: Option<&Membership>) -> bool {
    let Some(m) = membership else {
        return true;
    };
    let exempt_roles: &[i64] = match policy.kind {
        kind::MASTER_PASSWORD
        | kind::PASSWORD_GENERATOR
        | kind::FREE_FAMILIES_SPONSORSHIP
        | kind::REMOVE_UNLOCK_WITH_PIN
        | kind::RESTRICTED_ITEM_TYPES
        | kind::AUTOMATIC_APP_LOG_IN
        | kind::AUTOMATIC_USER_CONFIRMATION
        | kind::ORGANIZATION_USER_NOTIFICATION => &[],
        kind::MAXIMUM_VAULT_TIMEOUT => &[OWNER],
        _ => &[OWNER, ADMIN],
    };
    m.enabled
        && m.use_policies
        && matches!(m.status, ACCEPTED | CONFIRMED)
        && !exempt_roles.contains(&m.role)
        && !m.provider
}

/// A number that may arrive as a JSON number or a numeric string.
fn number(value: &Value, key: &str) -> Option<i64> {
    match field(value, key)? {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// A non-negative count from policy data.
fn count(data: &Value, key: &str) -> Option<u32> {
    number(data, key).and_then(|n| u32::try_from(n.max(0)).ok())
}

fn flag(data: &Value, key: &str) -> bool {
    field(data, key).and_then(Value::as_bool) == Some(true)
}

/// Raises each minimum and switches on each requirement, as Bitwarden's
/// `passwordLeastPrivilege` and `passphraseLeastPrivilege` do. A forced
/// password generator wins over a forced passphrase (`availableAlgorithms`).
fn merge_generator(policy: &mut GeneratorPolicy, data: &Value) {
    let raise = |current: &mut u32, key: &str| {
        if let Some(n) = count(data, key) {
            *current = (*current).max(n);
        }
    };
    raise(&mut policy.min_length, "minLength");
    raise(&mut policy.min_numbers, "minNumbers");
    raise(&mut policy.min_special, "minSpecial");
    raise(&mut policy.min_words, "minNumberWords");
    policy.use_upper |= flag(data, "useUpper");
    policy.use_lower |= flag(data, "useLower");
    policy.use_numbers |= flag(data, "useNumbers");
    policy.use_special |= flag(data, "useSpecial");
    policy.capitalize |= flag(data, "capitalize");
    policy.include_number |= flag(data, "includeNumber");
    // Older policies call the setting `defaultType`.
    let forced = field_str(data, "overridePasswordType").or_else(|| field_str(data, "defaultType"));
    let forced = match forced {
        Some("password") => Some(GeneratorType::Password),
        Some("passphrase") => Some(GeneratorType::Passphrase),
        _ => None,
    };
    if policy.forced_type != Some(GeneratorType::Password) && forced.is_some() {
        policy.forced_type = forced;
    }
}

/// Keeps the strictest of each limit. Bitwarden's clients apply only the
/// first maximum timeout policy they find; Hushjar combines them all.
fn merge_timeout(policy: &mut VaultTimeoutPolicy, data: &Value) {
    match field_str(data, "type") {
        Some("immediately") => policy.immediately = true,
        Some("onSystemLock") => policy.on_system_lock = true,
        Some("onAppRestart") => policy.on_app_restart = true,
        Some("never") => {}
        // "custom", or older policies with only minutes.
        _ => {
            if let Some(minutes) = count(data, "minutes") {
                policy.max_minutes = Some(policy.max_minutes.map_or(minutes, |m| m.min(minutes)));
            }
        }
    }
    let action = match field_str(data, "action") {
        Some(a) if a.eq_ignore_ascii_case("logOut") => Some(TimeoutAction::LogOut),
        Some(a) if a.eq_ignore_ascii_case("lock") => Some(TimeoutAction::Lock),
        _ => None,
    };
    if policy.action != Some(TimeoutAction::LogOut) && action.is_some() {
        policy.action = action;
    }
}

/// Highest minimums and any requirement, as `mergeMasterPasswordPolicyOptions`.
fn merge_master_password(policy: &mut MasterPasswordPolicy, data: &Value) {
    if let Some(n) = count(data, "minComplexity") {
        policy.min_complexity = policy.min_complexity.max(n);
    }
    if let Some(n) = count(data, "minLength") {
        policy.min_length = policy.min_length.max(n);
    }
    policy.require_upper |= flag(data, "requireUpper");
    policy.require_lower |= flag(data, "requireLower");
    policy.require_numbers |= flag(data, "requireNumbers");
    policy.require_special |= flag(data, "requireSpecial");
    policy.enforce_on_login |= flag(data, "enforceOnLogin");
}

/// Item types restricted by any organisation, and the organisations that
/// still allow each, as Bitwarden's `RestrictedItemTypesService`: the data is
/// a list of item type numbers, cards when missing.
fn restricted_item_types(
    enforced: &[Policy],
    memberships: &HashMap<String, Membership>,
) -> Vec<RestrictedItemType> {
    let restricting: Vec<(&str, Vec<u8>)> = enforced
        .iter()
        .filter(|p| p.kind == kind::RESTRICTED_ITEM_TYPES)
        .map(|p| {
            let types = match p.data.as_array() {
                Some(list) => list
                    .iter()
                    .filter_map(Value::as_u64)
                    .filter_map(|n| u8::try_from(n).ok())
                    .collect(),
                None => vec![CARD],
            };
            (p.organization.as_str(), types)
        })
        .collect();
    let mut types: Vec<u8> = restricting.iter().flat_map(|(_, t)| t.clone()).collect();
    types.sort_unstable();
    types.dedup();
    let mut organizations: Vec<&String> = memberships.keys().collect();
    organizations.sort();
    types
        .into_iter()
        .map(|item_type| RestrictedItemType {
            item_type,
            allowed_in: organizations
                .iter()
                .filter(|org| {
                    !restricting
                        .iter()
                        .any(|(o, t)| o == *org && t.contains(&item_type))
                })
                .map(|org| (*org).clone())
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A membership shaped like Vaultwarden's sync `profile.organizations`.
    fn org(id: &str, role: i64) -> Value {
        json!({
            "id": id, "name": "Org", "type": role, "status": 2, "enabled": true,
            "usePolicies": true, "object": "profileOrganization",
        })
    }

    fn policy(org: &str, kind: u8, data: Value) -> Value {
        json!({
            "id": uuid::Uuid::new_v4().to_string(), "organizationId": org, "type": kind,
            "data": data, "enabled": true, "revisionDate": null, "object": "policy",
        })
    }

    fn sync(orgs: Vec<Value>, policies: Vec<Value>) -> Value {
        json!({ "profile": { "id": "u", "organizations": orgs }, "policies": policies })
    }

    #[test]
    fn no_policies() {
        let p = Policies::from_sync(&json!({ "profile": {} }));
        assert_eq!(p, Policies::default());
        assert!(!p.applies(kind::DISABLE_SEND));
    }

    #[test]
    fn generator_minimums_combine_strictest() {
        let p = Policies::from_sync(&sync(
            vec![org("a", USER), org("b", USER)],
            vec![
                policy(
                    "a",
                    2,
                    json!({
                        "overridePasswordType": "passphrase", "minLength": 14,
                        "useUpper": true, "useLower": null, "useNumbers": false,
                        "useSpecial": null, "minNumbers": 2, "minSpecial": null,
                        "minNumberWords": 4, "capitalize": true, "includeNumber": false,
                    }),
                ),
                policy(
                    "b",
                    2,
                    json!({
                        "defaultType": "password", "minLength": "12", "useSpecial": true,
                        "minSpecial": 3, "minNumbers": 1, "minNumberWords": 6,
                        "includeNumber": true,
                    }),
                ),
            ],
        ));
        assert_eq!(
            p.generator,
            Some(GeneratorPolicy {
                forced_type: Some(GeneratorType::Password),
                min_length: 14,
                use_upper: true,
                use_lower: false,
                use_numbers: false,
                use_special: true,
                min_numbers: 2,
                min_special: 3,
                min_words: 6,
                capitalize: true,
                include_number: true,
            })
        );
        assert_eq!(p.enforced[&kind::PASSWORD_GENERATOR], vec!["a", "b"]);
    }

    #[test]
    fn owners_and_admins_are_exempt_where_bitwarden_exempts_them() {
        let policies = vec![
            policy("o", 5, Value::Null),
            policy("o", 6, Value::Null),
            policy("o", 7, json!({ "disableHideEmail": true })),
            policy("o", 10, Value::Null),
            policy("o", 9, json!({ "minutes": 30, "action": "lock" })),
            policy("o", 2, json!({ "minLength": 20 })),
            policy("o", 1, json!({ "minLength": 12, "enforceOnLogin": true })),
            policy("o", 14, Value::Null),
        ];
        let owner = Policies::from_sync(&sync(vec![org("o", OWNER)], policies.clone()));
        assert!(!owner.personal_ownership_disabled);
        assert!(!owner.send_disabled);
        assert!(!owner.send_hide_email_disabled);
        assert!(!owner.personal_export_disabled);
        assert!(owner.vault_timeout.is_none(), "owners are exempt");
        assert_eq!(owner.generator.unwrap().min_length, 20);
        assert!(owner.master_password.unwrap().enforce_on_login);
        assert!(owner.pin_unlock_disabled);

        let admin = Policies::from_sync(&sync(vec![org("o", ADMIN)], policies.clone()));
        assert!(!admin.personal_ownership_disabled);
        assert_eq!(admin.vault_timeout.unwrap().max_minutes, Some(30));

        let user = Policies::from_sync(&sync(vec![org("o", USER)], policies.clone()));
        assert!(user.personal_ownership_disabled);
        assert!(user.send_disabled);
        assert!(user.send_hide_email_disabled);
        assert!(user.personal_export_disabled);
        assert_eq!(
            user.vault_timeout,
            Some(VaultTimeoutPolicy {
                max_minutes: Some(30),
                action: Some(TimeoutAction::Lock),
                ..Default::default()
            })
        );
        // Custom roles are not exempt.
        let custom = Policies::from_sync(&sync(vec![org("o", 4)], policies));
        assert!(custom.personal_ownership_disabled);
    }

    #[test]
    fn memberships_that_do_not_count() {
        let policies = vec![policy("o", 6, Value::Null)];
        let with = |membership: Value| {
            Policies::from_sync(&sync(vec![membership], policies.clone())).send_disabled
        };
        let mut invited = org("o", USER);
        invited["status"] = json!(0);
        assert!(!with(invited));
        let mut revoked = org("o", USER);
        revoked["status"] = json!(-1);
        assert!(!with(revoked));
        let mut accepted = org("o", USER);
        accepted["status"] = json!(1);
        assert!(with(accepted));
        let mut disabled = org("o", USER);
        disabled["enabled"] = json!(false);
        assert!(!with(disabled));
        let mut no_policies = org("o", USER);
        no_policies["usePolicies"] = json!(false);
        assert!(!with(no_policies));
        let mut provider = org("o", USER);
        provider["isProviderUser"] = json!(true);
        assert!(!with(provider));
        // A policy for an organisation the profile does not list still applies.
        assert!(Policies::from_sync(&sync(vec![], policies.clone())).send_disabled);
        // Disabled policies never apply.
        let mut off = policy("o", 6, Value::Null);
        off["enabled"] = json!(false);
        assert!(!Policies::from_sync(&sync(vec![org("o", USER)], vec![off])).send_disabled);
    }

    #[test]
    fn vault_timeouts_combine_strictest() {
        let p = Policies::from_sync(&sync(
            vec![org("a", USER), org("b", USER), org("c", USER)],
            vec![
                policy(
                    "a",
                    9,
                    json!({ "type": "custom", "minutes": 240, "action": "lock" }),
                ),
                policy("b", 9, json!({ "minutes": 60, "action": "logOut" })),
                policy("c", 9, json!({ "type": "onSystemLock", "action": "lock" })),
            ],
        ));
        assert_eq!(
            p.vault_timeout,
            Some(VaultTimeoutPolicy {
                max_minutes: Some(60),
                on_system_lock: true,
                action: Some(TimeoutAction::LogOut),
                ..Default::default()
            })
        );
        let p = Policies::from_sync(&sync(
            vec![org("a", USER)],
            vec![policy(
                "a",
                9,
                json!({ "type": "immediately", "action": null }),
            )],
        ));
        assert!(p.vault_timeout.as_ref().unwrap().immediately);
        assert_eq!(p.vault_timeout.unwrap().action, None);
    }

    #[test]
    fn send_controls_and_string_data() {
        let mut controls = policy("a", 21, Value::Null);
        controls["data"] = json!(r#"{"disableSend":false,"disableHideEmail":true}"#);
        let p = Policies::from_sync(&sync(vec![org("a", USER)], vec![controls]));
        assert!(!p.send_disabled);
        assert!(p.send_hide_email_disabled);
    }

    #[test]
    fn restricted_item_types() {
        let p = Policies::from_sync(&sync(
            vec![org("a", OWNER), org("b", USER), org("c", USER)],
            vec![policy("a", 15, Value::Null), policy("b", 15, json!([3, 4]))],
        ));
        assert_eq!(
            p.restricted_item_types,
            vec![
                RestrictedItemType {
                    item_type: 3,
                    allowed_in: vec!["c".into()],
                },
                RestrictedItemType {
                    item_type: 4,
                    allowed_in: vec!["a".into(), "c".into()],
                },
            ]
        );
    }

    #[test]
    fn pascal_case_fields() {
        let p = Policies::from_sync(&json!({
            "Profile": { "Organizations": [{ "Id": "a", "Type": 2, "Status": 2, "Enabled": true, "UsePolicies": true }] },
            "Policies": [{ "OrganizationId": "a", "Type": 10, "Enabled": true, "Data": null }],
        }));
        assert!(p.personal_export_disabled);
    }
}
