//! The generator pane, and the Generate button on password fields.

use hushjar_core::generator::{
    self as make, MINIMUM_PASSWORD_LENGTH, PassphraseOptions, PasswordOptions, UsernameOptions,
};
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
    pub(super) fn secret(&self) -> Result<Zeroizing<String>, String> {
        let result = if self.kind == Kind::Passphrase {
            make::passphrase(&self.passphrase)
        } else {
            make::password(&self.password)
        };
        result.map_err(|e| capitalise(&e.to_string()))
    }

    fn generate(&mut self) {
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
        state.generator.generate();
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
        g.generate();
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
        st.borrow_mut().generator.generate();
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
