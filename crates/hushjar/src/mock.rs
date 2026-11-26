//! Dummy vault data used by the tree tests. Nothing here is a real secret.

use crate::FieldKind;
use crate::model::{
    Account, AddKind, Collection, Field, FieldPath, Folder, Item, ItemType, Section,
};

struct ItemBuilder(Item);

impl ItemBuilder {
    fn new(id: &str, kind: ItemType, name: &str) -> Self {
        let mut item = Item::empty(id, kind, name);
        item.created = "12 March 2024".into();
        item.revised = "3 days ago".into();
        Self(item)
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
            Field::text("Username", username).at(FieldPath::Username),
            Field::secret("Password", password).at(FieldPath::Password),
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
