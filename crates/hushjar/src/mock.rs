//! Dummy vault data for the M0 prototype. Nothing here is a real secret.
//! The types are deliberately simple; hushjar-core will replace them.

use crate::{FieldKind, RowIcon};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemType {
    Login,
    Card,
    Identity,
    Note,
    SshKey,
}

impl ItemType {
    pub const ALL: [ItemType; 5] = [
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
            ItemType::Note => RowIcon::Note,
            ItemType::SshKey => RowIcon::SshKey,
        }
    }

    pub fn group_label(self) -> &'static str {
        match self {
            ItemType::Login => "Logins",
            ItemType::Card => "Cards",
            ItemType::Identity => "Identities",
            ItemType::Note => "Secure notes",
            ItemType::SshKey => "SSH keys",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            ItemType::Login => "login",
            ItemType::Card => "card",
            ItemType::Identity => "identity",
            ItemType::Note => "note",
            ItemType::SshKey => "ssh-key",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub label: String,
    pub value: String,
    pub kind: FieldKind,
    pub copyable: bool,
    pub removable: bool,
    pub label_editable: bool,
}

impl Field {
    fn new(label: &str, value: &str, kind: FieldKind) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            kind,
            copyable: !matches!(kind, FieldKind::Info | FieldKind::Boolean),
            removable: false,
            label_editable: false,
        }
    }

    pub fn text(label: &str, value: &str) -> Self {
        Self::new(label, value, FieldKind::Text)
    }

    pub fn secret(label: &str, value: &str) -> Self {
        Self::new(label, value, FieldKind::Secret)
    }

    pub fn url(value: &str) -> Self {
        Self {
            removable: true,
            ..Self::new("Website", value, FieldKind::Url)
        }
    }

    pub fn totp(secret: &str) -> Self {
        Self::new("Verification code", secret, FieldKind::Totp)
    }

    pub fn notes(value: &str) -> Self {
        Self::new("Notes", value, FieldKind::Multiline)
    }

    pub fn custom(label: &str, value: &str, kind: FieldKind) -> Self {
        Self {
            removable: true,
            label_editable: true,
            ..Self::new(label, value, kind)
        }
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
}

impl Section {
    fn new(title: &str, fields: Vec<Field>) -> Self {
        Self {
            title: title.into(),
            fields,
            add: None,
        }
    }

    fn addable(title: &str, fields: Vec<Field>, add: AddKind) -> Self {
        Self {
            title: title.into(),
            fields,
            add: Some(add),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub id: String,
    pub kind: ItemType,
    pub name: String,
    pub folder: Option<String>,
    pub collections: Vec<String>,
    pub favorite: bool,
    pub deleted: bool,
    pub archived: bool,
    pub sections: Vec<Section>,
    pub created: String,
    pub revised: String,
}

impl Item {
    pub fn field(&self, label: &str) -> Option<&Field> {
        self.sections
            .iter()
            .flat_map(|s| &s.fields)
            .find(|f| f.label == label)
    }

    /// A short line shown next to the name in the tree.
    pub fn subtitle(&self) -> String {
        let value = |label| {
            self.field(label)
                .map(|f| f.value.clone())
                .unwrap_or_default()
        };
        match self.kind {
            ItemType::Login => value("Username"),
            ItemType::Card => {
                let number = value("Number");
                let last4: String = number
                    .chars()
                    .filter(char::is_ascii_digit)
                    .rev()
                    .take(4)
                    .collect();
                let last4: String = last4.chars().rev().collect();
                format!("{} •• {last4}", value("Brand"))
            }
            ItemType::Identity => value("Email"),
            ItemType::Note => String::new(),
            ItemType::SshKey => value("Fingerprint").chars().take(14).collect(),
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

    /// An empty item of the given type, with the sections Bitwarden shows.
    pub fn blank(id: String, kind: ItemType, folder: Option<String>) -> Self {
        let sections = match kind {
            ItemType::Login => vec![
                Section::new(
                    "Login",
                    vec![
                        Field::text("Username", ""),
                        Field::secret("Password", ""),
                        Field::totp(""),
                    ],
                ),
                Section::addable("Websites", vec![Field::url("https://")], AddKind::Website),
                Section::new("Notes", vec![Field::notes("")]),
                Section::addable("Custom fields", vec![], AddKind::CustomField),
            ],
            _ => vec![
                Section::new("Notes", vec![Field::notes("")]),
                Section::addable("Custom fields", vec![], AddKind::CustomField),
            ],
        };
        Self {
            id,
            kind,
            name: String::new(),
            folder,
            collections: vec![],
            favorite: false,
            deleted: false,
            archived: false,
            sections,
            created: "Just now".into(),
            revised: "Just now".into(),
        }
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
}

struct ItemBuilder(Item);

impl ItemBuilder {
    fn new(id: &str, kind: ItemType, name: &str) -> Self {
        Self(Item {
            id: id.into(),
            kind,
            name: name.into(),
            folder: None,
            collections: vec![],
            favorite: false,
            deleted: false,
            archived: false,
            sections: vec![],
            created: "12 March 2024".into(),
            revised: "3 days ago".into(),
        })
    }

    fn folder(mut self, id: &str) -> Self {
        self.0.folder = Some(id.into());
        self
    }

    fn collections(mut self, ids: &[&str]) -> Self {
        self.0.collections = ids.iter().map(|s| (*s).into()).collect();
        self
    }

    fn favorite(mut self) -> Self {
        self.0.favorite = true;
        self
    }

    fn deleted(mut self) -> Self {
        self.0.deleted = true;
        self
    }

    fn archived(mut self) -> Self {
        self.0.archived = true;
        self
    }

    fn section(mut self, title: &str, fields: Vec<Field>) -> Self {
        self.0.sections.push(Section::new(title, fields));
        self
    }

    fn login(self, username: &str, password: &str, totp: &str, sites: &[&str]) -> Self {
        let mut fields = vec![
            Field::text("Username", username),
            Field::secret("Password", password),
        ];
        fields.push(Field::totp(totp));
        let sites = sites.iter().map(|s| Field::url(s)).collect();
        self.section("Login", fields).websites(sites)
    }

    fn websites(mut self, sites: Vec<Field>) -> Self {
        self.0
            .sections
            .push(Section::addable("Websites", sites, AddKind::Website));
        self
    }

    /// Adds notes and custom fields, which every item has, and finishes.
    fn finish(mut self, notes: &str, custom: Vec<Field>) -> Item {
        self.0
            .sections
            .push(Section::new("Notes", vec![Field::notes(notes)]));
        self.0.sections.push(Section::addable(
            "Custom fields",
            custom,
            AddKind::CustomField,
        ));
        self.0
    }
}

fn card(
    id: &str,
    name: &str,
    holder: &str,
    brand: &str,
    number: &str,
    expiry: &str,
) -> ItemBuilder {
    ItemBuilder::new(id, ItemType::Card, name).section(
        "Card",
        vec![
            Field::text("Cardholder", holder),
            Field::text("Brand", brand),
            Field::secret("Number", number),
            Field::text("Expiry", expiry),
            Field::secret("Security code", "123"),
        ],
    )
}

fn folders(names: &[(&str, &str)]) -> Vec<Folder> {
    names
        .iter()
        .map(|(id, name)| Folder {
            id: (*id).into(),
            name: (*name).into(),
        })
        .collect()
}

pub fn sample() -> Vec<Account> {
    use ItemType::*;

    let personal = Account {
        id: "p".into(),
        email: "sam@example.org".into(),
        server: "vault.example.org".into(),
        initials: "S".into(),
        tint: (0x2f, 0x6f, 0xdb),
        locked: false,
        folders: folders(&[
            ("work", "Work"),
            ("code", "Work/Code"),
            ("home", "Home"),
            ("money", "Finance"),
            ("travel", "Travel"),
        ]),
        collections: vec![],
        items: vec![
            ItemBuilder::new("github", Login, "GitHub")
                .folder("code")
                .favorite()
                .login("sam-dev", "correct-horse-battery-staple-42", "JBSWY3DPEHPK3PXP", &["https://github.com"])
                .finish(
                    "Recovery codes are printed and kept in the fireproof box.",
                    vec![Field::custom("Recovery email", "sam+github@example.org", FieldKind::Text)],
                ),
            ItemBuilder::new("gitlab", Login, "GitLab")
                .folder("code")
                .login("sam", "w1nter-Is-c0ming!", "", &["https://gitlab.com"])
                .finish("", vec![]),
            ItemBuilder::new("deploy", SshKey, "Deploy key")
                .folder("code")
                .section(
                    "SSH key",
                    vec![
                        Field::text("Public key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyNotARealKey sam@laptop"),
                        Field::text("Fingerprint", "SHA256:q9Vb3L1kz7cYpQ2mXoW8eR4tN6uA0sDfGhJk5lZxC1E"),
                        Field::secret("Private key", "(example private key, not a real one)"),
                    ],
                )
                .finish("Used by the staging deploy job.", vec![]),
            ItemBuilder::new("jira", Login, "Jira")
                .folder("work")
                .login("sam@work.example", "tickets-tickets-tickets", "", &["https://example.atlassian.net"])
                .finish("", vec![]),
            ItemBuilder::new("router", Login, "Router admin")
                .folder("home")
                .login("admin", "blinking-lights-77", "", &["http://192.168.1.1"])
                .finish("Factory reset button is on the back.", vec![]),
            ItemBuilder::new("wifi", Note, "Home Wi-Fi")
                .folder("home")
                .finish("Network: Honeycomb\nGuest network: Honeycomb-Guest", vec![
                    Field::custom("Password", "buzz-buzz-buzz", FieldKind::Secret),
                ]),
            ItemBuilder::new("films", Login, "Film streaming")
                .folder("home")
                .favorite()
                .login("sam@example.org", "popcorn-and-blankets", "", &["https://films.example.com"])
                .finish("", vec![]),
            card("visa", "Everyday Visa", "Sam Example", "Visa", "4111 1111 1111 1111", "08/2029")
                .folder("money")
                .favorite()
                .finish("", vec![]),
            ItemBuilder::new("bank", Login, "Bank")
                .folder("money")
                .login("10293847", "save-more-spend-less", "GEZDGNBVGY3TQOJQ", &["https://bank.example.com"])
                .finish("", vec![
                    Field::custom("Phone PIN", "4821", FieldKind::Secret),
                    Field::custom("Paperless statements", "true", FieldKind::Boolean),
                ]),
            ItemBuilder::new("passport", Identity, "Passport")
                .folder("travel")
                .section(
                    "Identity",
                    vec![
                        Field::text("Name", "Sam Example"),
                        Field::text("Email", "sam@example.org"),
                        Field::text("Phone", "+45 12 34 56 78"),
                        Field::secret("Passport number", "X12345678"),
                        Field::text("Address", "1 Honey Lane\n1000 Example City"),
                    ],
                )
                .finish("Expires in 2031.", vec![]),
            ItemBuilder::new("airline", Login, "Airline")
                .folder("travel")
                .login("SAM12345", "window-seat-please", "", &["https://air.example.com"])
                .finish("Frequent flyer number is the username.", vec![]),
            ItemBuilder::new("pancakes", Note, "Grandma's pancakes")
                .finish("3 eggs, 300 ml milk, 150 g flour, a pinch of salt.\nRest the batter for 30 minutes.", vec![]),
            ItemBuilder::new("forum", Login, "Old forum")
                .deleted()
                .login("sammy99", "hunter2", "", &["https://forum.example.net"])
                .finish("", vec![]),
            ItemBuilder::new("oldphone", Note, "Old phone backup")
                .archived()
                .finish("Backup PIN for the old phone.", vec![]),
        ],
    };

    let work = Account {
        id: "w".into(),
        email: "sam@work.example".into(),
        server: "bitwarden.eu".into(),
        initials: "W".into(),
        tint: (0x1d, 0x8f, 0x58),
        locked: false,
        folders: folders(&[("projects", "Projects")]),
        collections: vec![
            Collection {
                id: "eng".into(),
                organization: "Example Ltd".into(),
                name: "Engineering".into(),
            },
            Collection {
                id: "it".into(),
                organization: "Example Ltd".into(),
                name: "Shared IT".into(),
            },
        ],
        items: vec![
            ItemBuilder::new("aws", Login, "Cloud console")
                .collections(&["eng"])
                .login(
                    "sam.example",
                    "rotate-me-quarterly",
                    "MFRGGZDFMZTWQ2LK",
                    &["https://console.cloud.example"],
                )
                .finish("", vec![]),
            ItemBuilder::new("grafana", Login, "Grafana")
                .folder("projects")
                .collections(&["eng"])
                .login("sam", "graphs-go-up", "", &["https://grafana.work.example"])
                .finish("", vec![]),
            ItemBuilder::new("office-wifi", Note, "Office Wi-Fi")
                .collections(&["it"])
                .finish(
                    "Network: ExampleCorp",
                    vec![Field::custom(
                        "Password",
                        "meeting-room-7",
                        FieldKind::Secret,
                    )],
                ),
            ItemBuilder::new("printer", Login, "Printer admin")
                .collections(&["it"])
                .login(
                    "admin",
                    "paper-jam-again",
                    "",
                    &["https://printer.work.example"],
                )
                .finish("", vec![]),
            card(
                "corp-card",
                "Company card",
                "Sam Example",
                "Mastercard",
                "5555 5555 5555 4444",
                "02/2028",
            )
            .collections(&["it"])
            .finish("For conference travel only.", vec![]),
            ItemBuilder::new("vpn", Login, "VPN")
                .login("sam", "tunnel-vision", "", &["https://vpn.work.example"])
                .finish("", vec![]),
        ],
    };

    let family = Account {
        id: "f".into(),
        email: "family@example.org".into(),
        server: "bitwarden.com".into(),
        initials: "F".into(),
        tint: (0xb0, 0x47, 0x9b),
        locked: true,
        folders: folders(&[("kids", "Kids")]),
        collections: vec![],
        items: vec![
            ItemBuilder::new("tv", Login, "TV streaming")
                .login(
                    "family@example.org",
                    "sofa-time",
                    "",
                    &["https://tv.example.com"],
                )
                .finish("", vec![]),
            ItemBuilder::new("tablet", Note, "Tablet PIN")
                .folder("kids")
                .finish("", vec![Field::custom("PIN", "2580", FieldKind::Secret)]),
            ItemBuilder::new("insurance", Note, "Home insurance")
                .finish("Policy HX-2231, renews every April.", vec![]),
        ],
    };

    vec![personal, work, family]
}
