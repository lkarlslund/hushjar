//! The generator pane, and the Generate button on password fields.

use hushjar_core::generator::{
    self as make, MINIMUM_PASSWORD_LENGTH, PassphraseOptions, PasswordOptions, UsernameOptions,
};
use hushjar_core::policy::{GeneratorPolicy, GeneratorType};
use serde_json::{Value, json};

use super::*;
use crate::{GeneratedValue, GeneratorData};

/// How many generated values the pane remembers.
const HISTORY: usize = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Password,
    Passphrase,
    Username,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Password => "Password",
            Kind::Passphrase => "Passphrase",
            Kind::Username => "Username",
        }
    }
}

/// The generator's settings and what it produced. History lives only in
/// memory and is cleared when everything locks.
pub(super) struct Generator {
    kind: Kind,
    password: PasswordOptions,
    passphrase: PassphraseOptions,
    username_kind: usize,
    username_capitalize: bool,
    username_number: bool,
    email: String,
    domain: String,
    value: Zeroizing<String>,
    error: String,
    history: VecDeque<(Zeroizing<String>, Kind, u64)>,
}

impl Generator {
    /// Reads the saved options (never values) from settings.json.
    pub(super) fn from_settings(settings: &Value) -> Self {
        let g = settings.get("generator");
        let get = |key: &str| g.and_then(|g| g.get(key)).cloned();
        let password = get("password")
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let passphrase = get("passphrase")
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or(PassphraseOptions {
                num_words: 6,
                word_separator: "-".into(),
                capitalize: false,
                include_number: false,
            });
        let flag = |key: &str| get(key).and_then(|v| v.as_bool()).unwrap_or(false);
        let text = |key: &str| {
            get(key)
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default()
        };
        Self {
            kind: match get("kind").and_then(|v| v.as_u64()) {
                Some(1) => Kind::Passphrase,
                Some(2) => Kind::Username,
                _ => Kind::Password,
            },
            password,
            passphrase,
            username_kind: get("username_kind")
                .and_then(|v| v.as_u64())
                .map(|v| v.min(2) as usize)
                .unwrap_or(0),
            username_capitalize: flag("username_capitalize"),
            username_number: flag("username_number"),
            email: text("email"),
            domain: text("domain"),
            value: Zeroizing::new(String::new()),
            error: String::new(),
            history: VecDeque::new(),
        }
    }

    fn store_into(&self, settings: &mut Value) {
        if !settings.is_object() {
            *settings = json!({});
        }
        settings["generator"] = json!({
            "kind": match self.kind { Kind::Password => 0, Kind::Passphrase => 1, Kind::Username => 2 },
            "password": self.password,
            "passphrase": self.passphrase,
            "username_kind": self.username_kind,
            "username_capitalize": self.username_capitalize,
            "username_number": self.username_number,
            "email": self.email,
            "domain": self.domain,
        });
    }

    /// A new secret for a password field: a passphrase when that is the
    /// chosen kind, otherwise a password.
    pub(super) fn secret(
        &self,
        policy: Option<&GeneratorPolicy>,
    ) -> Result<Zeroizing<String>, String> {
        let mut copy = self.settings();
        copy.apply(policy);
        let result = if copy.kind == Kind::Passphrase {
            make::passphrase(&copy.passphrase)
        } else {
            make::password(&copy.password)
        };
        result.map_err(|e| capitalise(&e.to_string()))
    }

    /// The options that decide what is generated, without the rest.
    fn settings(&self) -> Choices {
        Choices {
            kind: self.kind,
            password: self.password.clone(),
            passphrase: self.passphrase.clone(),
        }
    }

    /// Raises the options to what the organisation policy requires.
    fn enforce(&mut self, policy: Option<&GeneratorPolicy>) {
        let mut choices = self.settings();
        choices.apply(policy);
        self.kind = choices.kind;
        self.password = choices.password;
        self.passphrase = choices.passphrase;
    }

    fn generate(&mut self, policy: Option<&GeneratorPolicy>) {
        self.enforce(policy);
        let result = match self.kind {
            Kind::Password => make::password(&self.password),
            Kind::Passphrase => make::passphrase(&self.passphrase),
            Kind::Username => make::username(&self.username_options()).map(Zeroizing::new),
        };
        match result {
            Ok(value) => {
                self.error.clear();
                self.value = value;
            }
            Err(e) => {
                self.error = capitalise(&e.to_string());
                self.value = Zeroizing::new(String::new());
            }
        }
    }

    fn username_options(&self) -> UsernameOptions {
        match self.username_kind {
            1 => UsernameOptions::PlusAddressed {
                email: self.email.trim().to_string(),
            },
            2 => UsernameOptions::CatchAll {
                domain: self.domain.trim().trim_start_matches('@').to_string(),
            },
            _ => UsernameOptions::Word {
                capitalize: self.username_capitalize,
                include_number: self.username_number,
            },
        }
    }

    /// Remembers a value that was used (copied or put into a field).
    pub(super) fn remember(&mut self, value: &str, kind: Kind) {
        if value.is_empty() || self.history.front().is_some_and(|(v, ..)| **v == value) {
            return;
        }
        self.history
            .push_front((Zeroizing::new(value.to_string()), kind, unix_now()));
        self.history.truncate(HISTORY);
    }

    /// Remembers a secret made by [`Generator::secret`].
    pub(super) fn remember_secret(&mut self, value: &str) {
        let kind = if self.kind == Kind::Passphrase {
            Kind::Passphrase
        } else {
            Kind::Password
        };
        self.remember(value, kind);
    }

    pub(super) fn forget_history(&mut self) {
        self.history.clear();
    }
}

/// The generator options an organisation policy can change.
#[derive(Clone, Debug, PartialEq)]
struct Choices {
    kind: Kind,
    password: PasswordOptions,
    passphrase: PassphraseOptions,
}

impl Choices {
    fn apply(&mut self, policy: Option<&GeneratorPolicy>) {
        let Some(policy) = policy else { return };
        match (policy.forced_type, self.kind) {
            (Some(GeneratorType::Password), Kind::Passphrase) => self.kind = Kind::Password,
            (Some(GeneratorType::Passphrase), Kind::Password) => self.kind = Kind::Passphrase,
            _ => {}
        }
        raise_password(&mut self.password, policy);
        raise_passphrase(&mut self.passphrase, policy);
    }
}

fn small(n: u32) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

/// Lifts password options to the policy's minimums: never shorter, never
/// fewer sets, never fewer numbers or symbols than required.
fn raise_password(options: &mut PasswordOptions, policy: &GeneratorPolicy) {
    options.uppercase |= policy.use_upper;
    options.lowercase |= policy.use_lower;
    options.numbers |= policy.use_numbers;
    options.special |= policy.use_special;
    if policy.use_upper {
        options.min_uppercase = options.min_uppercase.max(1);
    }
    if policy.use_lower {
        options.min_lowercase = options.min_lowercase.max(1);
    }
    let numbers = small(policy.min_numbers).max(u8::from(policy.use_numbers));
    if numbers > 0 {
        options.numbers = true;
        options.min_number = options.min_number.max(numbers);
    }
    let special = small(policy.min_special).max(u8::from(policy.use_special));
    if special > 0 {
        options.special = true;
        options.min_special = options.min_special.max(special);
    }
    options.length = options.length.max(small(policy.min_length));
    // The required characters must fit in the password.
    let required = [
        options.min_uppercase,
        options.min_lowercase,
        options.min_number,
        options.min_special,
    ]
    .iter()
    .fold(0u8, |sum, n| sum.saturating_add(*n));
    options.length = options.length.max(required).min(128);
}

fn raise_passphrase(options: &mut PassphraseOptions, policy: &GeneratorPolicy) {
    options.num_words = options.num_words.max(small(policy.min_words)).min(20);
    options.capitalize |= policy.capitalize;
    options.include_number |= policy.include_number;
}

/// Combines the generator policies of several accounts: every requirement of
/// every policy holds. A forced passphrase applies only if nobody forces a
/// password (as for one account in the core).
pub(super) fn combine(policies: &[&GeneratorPolicy]) -> Option<GeneratorPolicy> {
    let mut all = policies.iter();
    let mut merged = (*all.next()?).clone();
    for p in all {
        merged.forced_type = match (merged.forced_type, p.forced_type) {
            (Some(GeneratorType::Password), _) | (_, Some(GeneratorType::Password)) => {
                Some(GeneratorType::Password)
            }
            (a, b) => a.or(b),
        };
        merged.min_length = merged.min_length.max(p.min_length);
        merged.use_upper |= p.use_upper;
        merged.use_lower |= p.use_lower;
        merged.use_numbers |= p.use_numbers;
        merged.use_special |= p.use_special;
        merged.min_numbers = merged.min_numbers.max(p.min_numbers);
        merged.min_special = merged.min_special.max(p.min_special);
        merged.min_words = merged.min_words.max(p.min_words);
        merged.capitalize |= p.capitalize;
        merged.include_number |= p.include_number;
    }
    Some(merged)
}

/// The sentence under the generator options that names what the
/// organisation requires for the chosen kind, or nothing.
pub(super) fn policy_note(policy: &GeneratorPolicy, kind: Kind) -> String {
    let mut needs: Vec<String> = Vec::new();
    match kind {
        Kind::Username => return String::new(),
        Kind::Password => {
            if policy.min_length > 0 {
                needs.push(format!("at least {} characters", policy.min_length));
            }
            if policy.min_numbers > 0 {
                needs.push(format!("at least {} numbers", policy.min_numbers));
            } else if policy.use_numbers {
                needs.push("numbers".into());
            }
            if policy.min_special > 0 {
                needs.push(format!(
                    "at least {} special characters",
                    policy.min_special
                ));
            } else if policy.use_special {
                needs.push("special characters".into());
            }
            if policy.use_upper {
                needs.push("capital letters".into());
            }
            if policy.use_lower {
                needs.push("small letters".into());
            }
        }
        Kind::Passphrase => {
            if policy.min_words > 0 {
                needs.push(format!("at least {} words", policy.min_words));
            }
            if policy.capitalize {
                needs.push("capitalised words".into());
            }
            if policy.include_number {
                needs.push("a number".into());
            }
        }
    }
    let forced = match (policy.forced_type, kind) {
        (Some(GeneratorType::Password), Kind::Passphrase) => {
            "Your organisation only allows passwords. "
        }
        (Some(GeneratorType::Passphrase), Kind::Password) => {
            "Your organisation only allows passphrases. "
        }
        _ => "",
    };
    if needs.is_empty() {
        return forced.trim_end().to_string();
    }
    let last = needs.pop().unwrap_or_default();
    let list = if needs.is_empty() {
        last
    } else {
        format!("{} and {last}", needs.join(", "))
    };
    format!("{forced}Your organisation requires {list}")
}

impl State {
    /// The generator rules of every unlocked account, combined.
    pub(super) fn generator_policy(&self) -> Option<GeneratorPolicy> {
        let found: Vec<&GeneratorPolicy> = self
            .accounts
            .iter()
            .filter(|a| a.vault.is_some())
            .filter_map(|a| a.policies.as_ref()?.generator.as_ref())
            .collect();
        combine(&found)
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

pub(super) fn show_generator(win: &AppWindow, st: &Shared) {
    if !leave_to(win, st, Pending::Generator) {
        return;
    }
    {
        let mut state = st.borrow_mut();
        state.shown = Shown::Generator;
        state.selected = None;
        let policy = state.generator_policy();
        state.generator.generate(policy.as_ref());
    }
    win.set_selected_key(SharedString::new());
    win.set_selected_index(-1);
    render(win, st);
}

pub(super) fn render_generator(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let g = &state.generator;
    let data = win.global::<GeneratorData>();
    data.set_kind(match g.kind {
        Kind::Password => 0,
        Kind::Passphrase => 1,
        Kind::Username => 2,
    });
    let p = &g.password;
    data.set_length(i32::from(p.length));
    data.set_uppercase(p.uppercase);
    data.set_lowercase(p.lowercase);
    data.set_numbers(p.numbers);
    data.set_special(p.special);
    data.set_min_numbers(i32::from(p.min_number));
    data.set_min_special(i32::from(p.min_special));
    data.set_avoid_ambiguous(p.avoid_ambiguous);
    data.set_minimum_length(i32::from(MINIMUM_PASSWORD_LENGTH));
    let pp = &g.passphrase;
    data.set_words(i32::from(pp.num_words));
    data.set_separator(s(&pp.word_separator));
    data.set_capitalize(pp.capitalize);
    data.set_include_number(pp.include_number);
    data.set_username_kind(g.username_kind as i32);
    data.set_username_capitalize(g.username_capitalize);
    data.set_username_number(g.username_number);
    data.set_email(s(&g.email));
    data.set_domain(s(&g.domain));
    data.set_policy_note(
        state
            .generator_policy()
            .map(|p| policy_note(&p, g.kind))
            .unwrap_or_default()
            .into(),
    );
    data.set_value(s(&g.value));
    data.set_error(s(&g.error));
    let now = unix_now();
    let history: Vec<GeneratedValue> = g
        .history
        .iter()
        .map(|(value, kind, at)| GeneratedValue {
            value: s(value),
            kind: s(kind.label()),
            when: s(&ago(now.saturating_sub(*at))),
        })
        .collect();
    data.set_history(ModelRc::new(VecModel::from(history)));
}

fn ago(seconds: u64) -> String {
    match seconds {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", seconds / 60),
        _ => format!("{} h ago", seconds / 3600),
    }
}

/// Reads the pane's options back, saves them and makes a new value.
fn generator_changed(win: &AppWindow, st: &Shared) {
    let data = win.global::<GeneratorData>();
    let clamp = |v: i32, lo: i32, hi: i32| v.clamp(lo, hi) as u8;
    {
        let mut state = st.borrow_mut();
        let policy = state.generator_policy();
        let g = &mut state.generator;
        g.kind = match data.get_kind() {
            1 => Kind::Passphrase,
            2 => Kind::Username,
            _ => Kind::Password,
        };
        g.password = PasswordOptions {
            length: clamp(data.get_length(), MINIMUM_PASSWORD_LENGTH.into(), 128),
            uppercase: data.get_uppercase(),
            lowercase: data.get_lowercase(),
            numbers: data.get_numbers(),
            special: data.get_special(),
            min_uppercase: u8::from(data.get_uppercase()),
            min_lowercase: u8::from(data.get_lowercase()),
            min_number: clamp(data.get_min_numbers(), 0, 9),
            min_special: clamp(data.get_min_special(), 0, 9),
            avoid_ambiguous: data.get_avoid_ambiguous(),
        };
        g.passphrase = PassphraseOptions {
            num_words: clamp(data.get_words(), 3, 20),
            word_separator: data.get_separator().chars().take(5).collect(),
            capitalize: data.get_capitalize(),
            include_number: data.get_include_number(),
        };
        g.username_kind = data.get_username_kind().clamp(0, 2) as usize;
        g.username_capitalize = data.get_username_capitalize();
        g.username_number = data.get_username_number();
        g.email = data.get_email().to_string();
        g.domain = data.get_domain().to_string();
        g.generate(policy.as_ref());
        let mut settings = state.store.read_settings();
        state.generator.store_into(&mut settings);
        let _ = state.store.write_settings(&settings);
    }
    render_generator(win, st);
}

pub(super) fn wire_generator(w: &AppWindow, state: &Shared) {
    let data = w.global::<GeneratorData>();
    let weak = w.as_weak();
    macro_rules! on {
        ($setter:ident, |$win:ident, $st:ident $(, $arg:ident : $ty:ty)*| $body:block) => {{
            let weak = weak.clone();
            let state = state.clone();
            data.$setter(move |$($arg: $ty),*| {
                let Some($win) = weak.upgrade() else { return };
                let $st = &state;
                $st.borrow_mut().last_activity = Instant::now();
                $body
            });
        }};
    }
    on!(on_changed, |win, st| {
        generator_changed(&win, st);
    });
    on!(on_regenerate, |win, st| {
        {
            let mut state = st.borrow_mut();
            let policy = state.generator_policy();
            state.generator.generate(policy.as_ref());
        }
        render_generator(&win, st);
    });
    on!(on_copy_value, |win, st| {
        let (value, kind) = {
            let g = &st.borrow().generator;
            (g.value.clone(), g.kind)
        };
        if value.is_empty() {
            return;
        }
        st.borrow_mut().generator.remember(&value, kind);
        let label = kind.label().to_lowercase();
        if kind == Kind::Username {
            copy_plain(&win, st, &value);
        } else {
            copy(&win, st, &value, &label);
        }
        render_generator(&win, st);
    });
    on!(on_copy_history, |win, st, index: i32| {
        let entry = st
            .borrow()
            .generator
            .history
            .get(index as usize)
            .map(|(v, k, _)| (v.clone(), *k));
        if let Some((value, kind)) = entry {
            copy(&win, st, &value, &kind.label().to_lowercase());
        }
    });
    on!(on_clear_history, |win, st| {
        st.borrow_mut().generator.forget_history();
        render_generator(&win, st);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> GeneratorPolicy {
        GeneratorPolicy::default()
    }

    #[test]
    fn password_options_are_raised_to_the_minimums() {
        let strict = GeneratorPolicy {
            min_length: 20,
            use_upper: true,
            use_numbers: true,
            min_numbers: 3,
            min_special: 2,
            ..policy()
        };
        let mut o = PasswordOptions {
            length: 12,
            uppercase: false,
            numbers: false,
            special: false,
            min_number: 0,
            min_special: 0,
            ..PasswordOptions::default()
        };
        raise_password(&mut o, &strict);
        assert_eq!(o.length, 20);
        assert!(o.uppercase && o.numbers && o.special);
        assert_eq!((o.min_number, o.min_special, o.min_uppercase), (3, 2, 1));
    }

    #[test]
    fn minimums_are_never_lowered() {
        let mut o = PasswordOptions {
            length: 40,
            min_number: 5,
            ..PasswordOptions::default()
        };
        raise_password(
            &mut o,
            &GeneratorPolicy {
                min_length: 14,
                min_numbers: 1,
                ..policy()
            },
        );
        assert_eq!((o.length, o.min_number), (40, 5));
    }

    #[test]
    fn required_characters_must_fit_the_length() {
        let mut o = PasswordOptions {
            length: 8,
            ..PasswordOptions::default()
        };
        raise_password(
            &mut o,
            &GeneratorPolicy {
                min_numbers: 9,
                min_special: 9,
                ..policy()
            },
        );
        assert!(o.length >= 18);
    }

    #[test]
    fn passphrase_options_are_raised() {
        let mut o = PassphraseOptions {
            num_words: 3,
            word_separator: "-".into(),
            capitalize: false,
            include_number: false,
        };
        raise_passphrase(
            &mut o,
            &GeneratorPolicy {
                min_words: 5,
                capitalize: true,
                include_number: true,
                ..policy()
            },
        );
        assert_eq!(
            (o.num_words, o.capitalize, o.include_number),
            (5, true, true)
        );
    }

    #[test]
    fn a_forced_type_switches_the_kind() {
        let mut c = Choices {
            kind: Kind::Passphrase,
            password: PasswordOptions::default(),
            passphrase: PassphraseOptions::default(),
        };
        c.apply(Some(&GeneratorPolicy {
            forced_type: Some(GeneratorType::Password),
            ..policy()
        }));
        assert_eq!(c.kind, Kind::Password);
        // Usernames are not passwords, so they stay available.
        c.kind = Kind::Username;
        c.apply(Some(&GeneratorPolicy {
            forced_type: Some(GeneratorType::Passphrase),
            ..policy()
        }));
        assert_eq!(c.kind, Kind::Username);
        c.kind = Kind::Password;
        c.apply(Some(&GeneratorPolicy {
            forced_type: Some(GeneratorType::Passphrase),
            ..policy()
        }));
        assert_eq!(c.kind, Kind::Passphrase);
        c.kind = Kind::Username;
        c.apply(None);
        assert_eq!(c.kind, Kind::Username);
    }

    #[test]
    fn policies_of_several_accounts_combine() {
        assert_eq!(combine(&[]), None);
        let a = GeneratorPolicy {
            min_length: 14,
            forced_type: Some(GeneratorType::Passphrase),
            ..policy()
        };
        let b = GeneratorPolicy {
            min_length: 20,
            use_special: true,
            ..policy()
        };
        let c = combine(&[&a, &b]).unwrap();
        assert_eq!((c.min_length, c.use_special), (20, true));
        assert_eq!(c.forced_type, Some(GeneratorType::Passphrase));
        let d = GeneratorPolicy {
            forced_type: Some(GeneratorType::Password),
            ..policy()
        };
        assert_eq!(
            combine(&[&a, &d]).unwrap().forced_type,
            Some(GeneratorType::Password)
        );
    }

    #[test]
    fn the_note_names_the_requirements() {
        let p = GeneratorPolicy {
            min_length: 14,
            use_numbers: true,
            ..policy()
        };
        assert_eq!(
            policy_note(&p, Kind::Password),
            "Your organisation requires at least 14 characters and numbers"
        );
        assert_eq!(
            policy_note(
                &GeneratorPolicy {
                    min_length: 14,
                    ..policy()
                },
                Kind::Password
            ),
            "Your organisation requires at least 14 characters"
        );
        assert_eq!(policy_note(&p, Kind::Username), "");
        assert_eq!(policy_note(&policy(), Kind::Password), "");
        let only = GeneratorPolicy {
            forced_type: Some(GeneratorType::Passphrase),
            ..policy()
        };
        assert_eq!(
            policy_note(&only, Kind::Password),
            "Your organisation only allows passphrases."
        );
    }

    #[test]
    fn a_generated_secret_meets_the_policy() {
        let g = Generator::from_settings(&json!({}));
        let p = GeneratorPolicy {
            min_length: 24,
            min_numbers: 4,
            ..policy()
        };
        let secret = g.secret(Some(&p)).unwrap();
        assert!(secret.len() >= 24);
        assert!(secret.chars().filter(char::is_ascii_digit).count() >= 4);
    }
}
