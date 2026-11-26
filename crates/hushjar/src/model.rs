//! What the UI shows: accounts and items arranged as titled sections of
//! fields. Items are converted from hushjar-core's vault, and edits are
//! written back to a core item through each field's [`FieldPath`].

use hushjar_core::store::Profile;
use hushjar_core::vault::{self as core, FieldType, IDENTITY_FIELDS, ItemKind};

use crate::{FieldKind, RowIcon};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemType {
    Login,
    Card,
    Identity,
    Note,
    SshKey,
    Other,
}

impl ItemType {
    /// Types shown as groups, in order. Unknown types join "Other".
    pub const ALL: [ItemType; 6] = [
        ItemType::Login,
        ItemType::Card,
        ItemType::Identity,
        ItemType::Note,
        ItemType::SshKey,
        ItemType::Other,
    ];
    /// Types a new item can have.
    pub const CREATABLE: [ItemType; 5] = [
        ItemType::Login,
        ItemType::Card,
        ItemType::Identity,
        ItemType::Note,
        ItemType::SshKey,
    ];

    pub fn icon(self) -> RowIcon {
        match self {
            ItemType::Login => RowIcon::Login,
            ItemType::Card => RowIcon::Card,
            ItemType::Identity => RowIcon::Identity,
            ItemType::Note | ItemType::Other => RowIcon::Note,
            ItemType::SshKey => RowIcon::SshKey,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ItemType::Login => "Login",
            ItemType::Card => "Card",
            ItemType::Identity => "Identity",
            ItemType::Note => "Note",
            ItemType::SshKey => "SSH key",
            ItemType::Other => "Other",
        }
    }

    pub fn group_label(self) -> &'static str {
        match self {
            ItemType::Login => "Logins",
            ItemType::Card => "Cards",
            ItemType::Identity => "Identities",
            ItemType::Note => "Secure notes",
            ItemType::SshKey => "SSH keys",
            ItemType::Other => "Other",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            ItemType::Login => "login",
            ItemType::Card => "card",
            ItemType::Identity => "identity",
            ItemType::Note => "note",
            ItemType::SshKey => "ssh-key",
            ItemType::Other => "other",
        }
    }

    pub fn from_kind(kind: ItemKind) -> Self {
        match kind {
            ItemKind::Login => ItemType::Login,
            ItemKind::Card => ItemType::Card,
            ItemKind::Identity => ItemType::Identity,
            ItemKind::SecureNote => ItemType::Note,
            ItemKind::SshKey => ItemType::SshKey,
            ItemKind::Other(_) => ItemType::Other,
        }
    }

    pub fn to_kind(self) -> ItemKind {
        match self {
            ItemType::Login => ItemKind::Login,
            ItemType::Card => ItemKind::Card,
            ItemType::Identity => ItemKind::Identity,
            ItemType::Note | ItemType::Other => ItemKind::SecureNote,
            ItemType::SshKey => ItemKind::SshKey,
        }
    }
}

/// Where a field's value lives in a core item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldPath {
    Username,
    Password,
    Totp,
    /// A website; the index of the original address, if it existed.
    Uri(Option<usize>),
    Notes,
    CardholderName,
    Brand,
    Number,
    ExpMonth,
    ExpYear,
    Code,
    Identity(&'static str),
    SshPrivate,
    SshPublic,
    SshFingerprint,
    /// A custom field; the index of the original field, if it existed.
    Custom(Option<usize>),
    /// Shown only, never written back.
    Info,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub label: String,
    pub value: String,
    pub kind: FieldKind,
    pub copyable: bool,
    pub removable: bool,
    pub label_editable: bool,
    pub path: FieldPath,
}

impl Field {
    pub fn new(label: &str, value: &str, kind: FieldKind, path: FieldPath) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            kind,
            copyable: !matches!(kind, FieldKind::Info | FieldKind::Boolean),
            removable: false,
            label_editable: false,
            path,
        }
    }

    #[cfg(test)]
    pub fn text(label: &str, value: &str) -> Self {
        Self::new(label, value, FieldKind::Text, FieldPath::Info)
    }

    pub fn secret(label: &str, value: &str) -> Self {
        Self::new(label, value, FieldKind::Secret, FieldPath::Info)
    }

    pub fn url(value: &str) -> Self {
        Self {
            removable: true,
            ..Self::new("Website", value, FieldKind::Url, FieldPath::Uri(None))
        }
    }

    #[cfg(test)]
    pub fn totp(secret: &str) -> Self {
        Self::new(
            "Verification code",
            secret,
            FieldKind::Totp,
            FieldPath::Totp,
        )
    }

    pub fn notes(value: &str) -> Self {
        Self::new("Notes", value, FieldKind::Multiline, FieldPath::Notes)
    }

    pub fn custom(label: &str, value: &str, kind: FieldKind) -> Self {
        Self {
            removable: true,
            label_editable: true,
            ..Self::new(label, value, kind, FieldPath::Custom(None))
        }
    }

    pub fn info(label: &str, value: &str) -> Self {
        Self::new(label, value, FieldKind::Info, FieldPath::Info)
    }

    pub fn at(mut self, path: FieldPath) -> Self {
        self.path = path;
        self
    }

    /// Whether the filter may look at this field. Secrets are never searched.
    pub fn searchable(&self) -> bool {
        matches!(
            self.kind,
            FieldKind::Text | FieldKind::Url | FieldKind::Multiline
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddKind {
    Website,
    CustomField,
}

impl AddKind {
    pub fn label(self) -> &'static str {
        match self {
            AddKind::Website => "Add website",
            AddKind::CustomField => "Add field",
        }
    }

    pub fn new_field(self) -> Field {
        match self {
            AddKind::Website => Field::url("https://"),
            AddKind::CustomField => Field::custom("New field", "", FieldKind::Text),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Section {
    pub title: String,
    pub fields: Vec<Field>,
    pub add: Option<AddKind>,
    /// Shown when viewing, left out while editing.
    pub view_only: bool,
}

impl Section {
    pub fn new(title: &str, fields: Vec<Field>) -> Self {
        Self {
            title: title.into(),
            fields,
            add: None,
            view_only: false,
        }
    }

    pub fn addable(title: &str, fields: Vec<Field>, add: AddKind) -> Self {
        Self {
            title: title.into(),
            fields,
            add: Some(add),
            view_only: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub id: String,
    pub kind: ItemType,
    pub name: String,
    pub folder: Option<String>,
    pub organization: Option<String>,
    pub collections: Vec<String>,
    pub favorite: bool,
    pub deleted: bool,
    pub archived: bool,
    /// Ask for the master password before showing or copying secrets.
    pub reprompt: bool,
    pub editable: bool,
    pub sections: Vec<Section>,
    pub created: String,
    pub revised: String,
}

impl Item {
    #[cfg(test)]
    pub fn empty(id: &str, kind: ItemType, name: &str) -> Self {
        Self {
            id: id.into(),
            kind,
            name: name.into(),
            folder: None,
            organization: None,
            collections: vec![],
            favorite: false,
            deleted: false,
            archived: false,
            reprompt: false,
            editable: true,
            sections: vec![],
            created: String::new(),
            revised: String::new(),
        }
    }

    pub fn field_at(&self, path: FieldPath) -> Option<&Field> {
        self.sections
            .iter()
            .flat_map(|s| &s.fields)
            .find(|f| f.path == path)
    }

    /// A short line shown next to the name in the tree.
    pub fn subtitle(&self) -> String {
        let value = |path| {
            self.field_at(path)
                .map(|f| f.value.clone())
                .unwrap_or_default()
        };
        match self.kind {
            ItemType::Login => value(FieldPath::Username),
            ItemType::Card => {
                let number = value(FieldPath::Number);
                let digits: Vec<char> = number.chars().filter(char::is_ascii_digit).collect();
                let last4: String = digits[digits.len().saturating_sub(4)..].iter().collect();
                let brand = value(FieldPath::Brand);
                match (brand.is_empty(), last4.is_empty()) {
                    (_, true) => brand,
                    (true, false) => format!("•• {last4}"),
                    (false, false) => format!("{brand} •• {last4}"),
                }
            }
            ItemType::Identity => value(FieldPath::Identity("email")),
            ItemType::Note | ItemType::Other => String::new(),
            ItemType::SshKey => value(FieldPath::SshFingerprint).chars().take(14).collect(),
        }
    }

    /// Case-insensitive match on the name, subtitle and non-secret fields.
    /// `needle` must already be lower case.
    pub fn matches(&self, needle: &str) -> bool {
        needle.is_empty()
            || self.name.to_lowercase().contains(needle)
            || self.subtitle().to_lowercase().contains(needle)
            || self
                .sections
                .iter()
                .flat_map(|s| &s.fields)
                .filter(|f| f.searchable())
                .any(|f| f.value.to_lowercase().contains(needle))
    }
}

#[derive(Clone, Debug)]
pub struct Folder {
    pub id: String,
    /// Bitwarden nests folders by using `/` in the name.
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct Collection {
    pub id: String,
    pub organization: String,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub server: String,
    pub initials: String,
    pub tint: (u8, u8, u8),
    pub locked: bool,
    pub folders: Vec<Folder>,
    pub collections: Vec<Collection>,
    pub items: Vec<Item>,
}

impl Account {
    pub fn folder_name(&self, id: &str) -> Option<&str> {
        self.folders
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.name.as_str())
    }

    /// A locked account as listed before unlocking.
    pub fn locked(profile: &Profile) -> Self {
        Self {
            id: profile.id.clone(),
            email: profile.email.clone(),
            server: profile.server.name.clone(),
            initials: profile
                .email
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_default(),
            tint: (profile.tint[0], profile.tint[1], profile.tint[2]),
            locked: true,
            folders: vec![],
            collections: vec![],
            items: vec![],
        }
    }

    pub fn from_vault(profile: &Profile, vault: &core::Vault) -> Self {
        let org_name = |id: &str| {
            vault
                .organizations
                .iter()
                .find(|o| o.id == id)
                .map(|o| o.name.clone())
                .unwrap_or_else(|| "Organisation".into())
        };
        Self {
            locked: false,
            folders: vault
                .folders
                .iter()
                .map(|f| Folder {
                    id: f.id.clone(),
                    name: f.name.clone(),
                })
                .collect(),
            collections: vault
                .collections
                .iter()
                .map(|c| Collection {
                    id: c.id.clone(),
                    organization: org_name(&c.organization_id),
                    name: c.name.clone(),
                })
                .collect(),
            items: vault.items.iter().map(from_core).collect(),
            ..Self::locked(profile)
        }
    }
}

/// Formats Bitwarden's ISO timestamps as "3 March 2026, 14:05 UTC".
pub fn format_time(iso: &str) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let parse =
        |range: std::ops::Range<usize>| iso.get(range).and_then(|s| s.parse::<usize>().ok());
    match (parse(0..4), parse(5..7), parse(8..10), iso.get(11..16)) {
        (Some(y), Some(m), Some(d), Some(time)) if (1..=12).contains(&m) => {
            format!("{d} {} {y}, {time} UTC", MONTHS[m - 1])
        }
        _ => iso.to_string(),
    }
}

/// Converts a decrypted core item into display sections.
pub fn from_core(item: &core::Item) -> Item {
    use FieldKind as K;
    use FieldPath as P;
    let kind = ItemType::from_kind(item.kind);
    let mut sections = Vec::new();
    let hidden_by_org = !item.view_password;
    match item.kind {
        ItemKind::Login => {
            let password = if hidden_by_org {
                Field::info("Password", "Hidden by your organisation")
            } else {
                Field::new("Password", &item.login.password, K::Secret, P::Password)
            };
            sections.push(Section::new(
                "Login",
                vec![
                    Field::new("Username", &item.login.username, K::Text, P::Username),
                    password,
                    Field::new("Verification code", &item.login.totp, K::Totp, P::Totp),
                ],
            ));
            let sites = item
                .login
                .uris
                .iter()
                .enumerate()
                .map(|(i, u)| Field::url(&u.uri).at(P::Uri(Some(i))))
                .collect();
            sections.push(Section::addable("Websites", sites, AddKind::Website));
            if item.login.passkeys > 0 {
                let text = if item.login.passkeys == 1 {
                    "1 passkey saved".to_string()
                } else {
                    format!("{} passkeys saved", item.login.passkeys)
                };
                sections.push(Section {
                    view_only: true,
                    ..Section::new("Passkeys", vec![Field::info("Passkey", &text)])
                });
            }
        }
        ItemKind::Card => {
            let c = &item.card;
            sections.push(Section::new(
                "Card",
                vec![
                    Field::new(
                        "Cardholder name",
                        &c.cardholder_name,
                        K::Text,
                        P::CardholderName,
                    ),
                    Field::new("Brand", &c.brand, K::Text, P::Brand),
                    Field::new("Number", &c.number, K::Secret, P::Number),
                    Field::new("Expiry month", &c.exp_month, K::Text, P::ExpMonth),
                    Field::new("Expiry year", &c.exp_year, K::Text, P::ExpYear),
                    Field::new("Security code", &c.code, K::Secret, P::Code),
                ],
            ));
        }
        ItemKind::Identity => {
            let fields = IDENTITY_FIELDS
                .iter()
                .map(|(name, label, secret)| {
                    Field::new(
                        label,
                        item.identity_value(name),
                        if *secret { K::Secret } else { K::Text },
                        P::Identity(name),
                    )
                })
                .collect();
            sections.push(Section::new("Identity", fields));
        }
        ItemKind::SshKey => {
            let k = &item.ssh_key;
            sections.push(Section::new(
                "SSH key",
                vec![
                    Field::new("Public key", &k.public_key, K::Text, P::SshPublic),
                    Field::new("Fingerprint", &k.fingerprint, K::Text, P::SshFingerprint),
                    Field::new("Private key", &k.private_key, K::Secret, P::SshPrivate),
                ],
            ));
        }
        ItemKind::SecureNote => {}
        ItemKind::Other(_) => sections.push(Section {
            view_only: true,
            ..Section::new(
                "Details",
                vec![Field::info(
                    "Type",
                    "This kind of item can be viewed and edited in other Bitwarden apps",
                )],
            )
        }),
    }
    sections.push(Section::new("Notes", vec![Field::notes(&item.notes)]));
    let custom = item
        .fields
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let kind = match f.kind {
                FieldType::Text => K::Text,
                FieldType::Hidden => K::Secret,
                FieldType::Boolean => K::Boolean,
                FieldType::Linked => K::Info,
            };
            let value = if f.kind == FieldType::Linked {
                "Linked to another field".to_string()
            } else {
                f.value.clone()
            };
            Field::custom(&f.name, &value, kind).at(P::Custom(Some(i)))
        })
        .collect();
    sections.push(Section::addable(
        "Custom fields",
        custom,
        AddKind::CustomField,
    ));
    if !item.password_history.is_empty() && !hidden_by_org {
        let entries = item
            .password_history
            .iter()
            .map(|h| {
                Field::secret(
                    &format!("Used until {}", format_time(&h.last_used)),
                    &h.password,
                )
            })
            .collect();
        sections.push(Section {
            view_only: true,
            ..Section::new("Password history", entries)
        });
    }
    Item {
        id: item.id.clone(),
        kind,
        name: item.name.clone(),
        folder: item.folder_id.clone(),
        organization: item.organization_id.clone(),
        collections: item.collection_ids.clone(),
        favorite: item.favorite,
        deleted: item.deleted,
        archived: item.archived,
        reprompt: item.reprompt,
        editable: item.editable && item.kind.editable() && item.unreadable == 0,
        sections,
        created: format_time(&item.created),
        revised: format_time(&item.revised),
    }
}

/// Writes an edited display item back onto its core original.
pub fn apply(display: &Item, original: &core::Item) -> core::Item {
    use FieldPath as P;
    let mut item = original.clone();
    item.name = display.name.clone();
    item.folder_id = display.folder.clone();
    item.favorite = display.favorite;
    item.reprompt = display.reprompt;
    let mut uris = Vec::new();
    let mut custom = Vec::new();
    for field in display
        .sections
        .iter()
        .filter(|s| !s.view_only)
        .flat_map(|s| &s.fields)
    {
        let v = field.value.clone();
        match field.path {
            P::Username => item.login.username = v,
            P::Password => item.login.password = v,
            P::Totp => item.login.totp = v.trim().to_string(),
            P::Uri(index) => {
                if !v.trim().is_empty() && v.trim() != "https://" {
                    let match_type = index
                        .and_then(|i| original.login.uris.get(i))
                        .and_then(|u| u.match_type);
                    uris.push(core::Uri {
                        uri: v.trim().to_string(),
                        match_type,
                    });
                }
            }
            P::Notes => item.notes = v,
            P::CardholderName => item.card.cardholder_name = v,
            P::Brand => item.card.brand = v,
            P::Number => item.card.number = v,
            P::ExpMonth => item.card.exp_month = v,
            P::ExpYear => item.card.exp_year = v,
            P::Code => item.card.code = v,
            P::Identity(name) => {
                if v.is_empty() {
                    item.identity.remove(name);
                } else {
                    item.identity.insert(name.to_string(), v);
                }
            }
            P::SshPrivate => item.ssh_key.private_key = v,
            P::SshPublic => item.ssh_key.public_key = v,
            P::SshFingerprint => item.ssh_key.fingerprint = v,
            P::Custom(index) => {
                let previous = index.and_then(|i| original.fields.get(i));
                let field = match previous {
                    Some(p) if p.kind == FieldType::Linked => core::CustomField {
                        name: field.label.clone(),
                        ..p.clone()
                    },
                    _ => core::CustomField {
                        name: field.label.clone(),
                        value: v,
                        kind: match field.kind {
                            FieldKind::Secret => FieldType::Hidden,
                            FieldKind::Boolean => FieldType::Boolean,
                            _ => FieldType::Text,
                        },
                        linked_id: None,
                    },
                };
                custom.push(field);
            }
            P::Info => {}
        }
    }
    if item.kind == ItemKind::Login {
        item.login.uris = uris;
    }
    item.fields = custom;
    item.note_password_change(original);
    item
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_round_trip_through_paths() {
        let mut original = core::Item::new(ItemKind::Login, None, None);
        original.name = "Mail".into();
        original.login.username = "sam".into();
        original.login.password = "old".into();
        original.login.uris = vec![core::Uri {
            uri: "https://mail.example".into(),
            match_type: Some(3),
        }];
        original.fields = vec![core::CustomField {
            name: "Link".into(),
            value: String::new(),
            kind: FieldType::Linked,
            linked_id: Some(100),
        }];

        let mut display = from_core(&original);
        display.name = "Mail (work)".into();
        for section in &mut display.sections {
            for field in &mut section.fields {
                if field.path == FieldPath::Password {
                    field.value = "new".into();
                }
            }
            if section.add == Some(AddKind::Website) {
                section.fields.push(Field::url("https://second.example"));
            }
            if section.add == Some(AddKind::CustomField) {
                section
                    .fields
                    .push(Field::custom("Extra", "x", FieldKind::Secret));
            }
        }
        let saved = apply(&display, &original);
        assert_eq!(saved.name, "Mail (work)");
        assert_eq!(saved.login.password, "new");
        assert_eq!(saved.password_history[0].password, "old");
        assert_eq!(saved.login.uris.len(), 2);
        assert_eq!(
            saved.login.uris[0].match_type,
            Some(3),
            "match settings survive"
        );
        assert_eq!(saved.fields[0].kind, FieldType::Linked);
        assert_eq!(saved.fields[0].linked_id, Some(100));
        assert_eq!(saved.fields[1].kind, FieldType::Hidden);
    }

    #[test]
    fn time_format() {
        assert_eq!(
            format_time("2026-03-03T14:05:09.123Z"),
            "3 March 2026, 14:05 UTC"
        );
        assert_eq!(format_time("soon"), "soon");
    }
}
