//! The pure parts of the import and export screen: formats, file names and
//! the sentences shown to the user. No windows and no I/O, so they can be
//! tested on their own.

use hushjar_core::exchange::import::{Format, ImportSummary, ParsedImport};

/// What an export file looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    EncryptedJson,
    PasswordProtectedJson,
    Csv,
}

impl ExportFormat {
    pub const ALL: [ExportFormat; 4] = [
        ExportFormat::Json,
        ExportFormat::EncryptedJson,
        ExportFormat::PasswordProtectedJson,
        ExportFormat::Csv,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ExportFormat::Json => "Bitwarden JSON",
            ExportFormat::EncryptedJson => "Bitwarden encrypted JSON (this account only)",
            ExportFormat::PasswordProtectedJson => "Password-protected JSON",
            ExportFormat::Csv => "CSV",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            _ => "json",
        }
    }

    /// Whether anyone holding the file can read the passwords in it.
    pub fn is_plain(self) -> bool {
        matches!(self, ExportFormat::Json | ExportFormat::Csv)
    }

    pub fn needs_file_password(self) -> bool {
        self == ExportFormat::PasswordProtectedJson
    }

    /// The default file name, such as `hushjar-export-2026-11-26.json`.
    pub fn file_name(self, unix_time: u64) -> String {
        let (y, m, d) = civil_date(unix_time);
        let kind = match self {
            ExportFormat::Json | ExportFormat::Csv => "export",
            ExportFormat::EncryptedJson => "encrypted-export",
            ExportFormat::PasswordProtectedJson => "protected-export",
        };
        format!("hushjar-{kind}-{y:04}-{m:02}-{d:02}.{}", self.extension())
    }
}

/// Whose items an export covers, owned so it can travel to the worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportScope {
    Personal,
    Organization(String),
}

/// Writes an export file readable by its owner only (on Unix), replacing any
/// file already there.
pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let mut file = options.open(path)?;
        // A file that existed keeps its old mode when opened; tighten it.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(data)?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        let mut file = options.open(path)?;
        file.write_all(data)?;
        file.sync_all()
    }
}

/// Year, month and day (UTC) of a Unix time.
fn civil_date(unix_time: u64) -> (i64, u32, u32) {
    let days = (unix_time / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The format box of the import card: automatic detection, then every format.
pub fn import_format_options() -> Vec<&'static str> {
    let mut options = vec!["Detect automatically"];
    options.extend(Format::ALL.iter().map(|f| f.label()));
    options
}

/// The format chosen at `index` of [`import_format_options`]; `None` means detect.
pub fn import_format_at(index: usize) -> Option<Format> {
    index
        .checked_sub(1)
        .and_then(|i| Format::ALL.get(i).copied())
}

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// "Found 42 items in 5 folders; 2 cannot be imported".
pub fn preview_text(parsed: &ParsedImport) -> String {
    let mut text = format!(
        "Found {} in {}",
        count(parsed.items.len(), "item", "items"),
        count(parsed.folders.len(), "folder", "folders")
    );
    if parsed.skipped > 0 {
        text.push_str(&format!("; {} cannot be imported", parsed.skipped));
    }
    text
}

/// The sentence shown after an import.
pub fn summary_text(summary: &ImportSummary) -> String {
    let mut text = format!("Imported {}", count(summary.items, "item", "items"));
    let (new, old) = (summary.folders_created, summary.folders_reused);
    match (new, old) {
        (0, 0) => {}
        (n, 0) => text.push_str(&format!(", and created {}", count(n, "folder", "folders"))),
        (0, o) => text.push_str(&format!(
            ", into {} you already had",
            count(o, "folder", "folders")
        )),
        (n, o) => text.push_str(&format!(
            ", and created {} (reused {o})",
            count(n, "folder", "folders")
        )),
    }
    if summary.skipped > 0 {
        text.push_str(&format!("; {} could not be imported", summary.skipped));
    }
    text.push('.');
    text
}

/// Where imported items go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Keep the folders the file has.
    FileFolders,
    /// No folder at all.
    Nowhere,
    /// All items into the folder of this name (created when missing).
    Folder(String),
}

/// Rewrites a parsed import so every item lands where `target` says.
pub fn apply_target(parsed: &mut ParsedImport, target: &Target) {
    match target {
        Target::FileFolders => {}
        Target::Nowhere => {
            parsed.folders.clear();
            parsed.items.iter_mut().for_each(|i| i.folder = None);
        }
        Target::Folder(name) => {
            parsed.folders = vec![name.clone()];
            parsed.items.iter_mut().for_each(|i| i.folder = Some(0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hushjar_core::exchange::import::ImportItem;
    use hushjar_core::vault::{Item, ItemKind};

    fn parsed(items: usize, folders: &[&str], skipped: usize) -> ParsedImport {
        ParsedImport {
            format: Format::BitwardenJson,
            items: (0..items)
                .map(|_| ImportItem {
                    item: Item::new(ItemKind::Login, None, None),
                    folder: Some(0),
                    passkeys: vec![],
                })
                .collect(),
            folders: folders.iter().map(|f| f.to_string()).collect(),
            skipped,
        }
    }

    #[test]
    fn file_names_carry_the_date_and_extension() {
        // 2026-11-26 12:00:00 UTC
        let t = 1_795_694_400;
        assert_eq!(
            ExportFormat::Json.file_name(t),
            "hushjar-export-2026-11-26.json"
        );
        assert_eq!(
            ExportFormat::Csv.file_name(t),
            "hushjar-export-2026-11-26.csv"
        );
        assert_eq!(
            ExportFormat::EncryptedJson.file_name(t),
            "hushjar-encrypted-export-2026-11-26.json"
        );
        assert_eq!(
            ExportFormat::Json.file_name(0),
            "hushjar-export-1970-01-01.json"
        );
        // A leap day.
        assert_eq!(civil_date(1_709_164_800), (2024, 2, 29));
    }

    #[cfg(unix)]
    #[test]
    fn export_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("hushjar-test-{}.json", std::process::id()));
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn only_plain_formats_warn() {
        let plain: Vec<_> = ExportFormat::ALL.iter().filter(|f| f.is_plain()).collect();
        assert_eq!(plain, [&ExportFormat::Json, &ExportFormat::Csv]);
        assert!(ExportFormat::PasswordProtectedJson.needs_file_password());
        assert!(!ExportFormat::Json.needs_file_password());
    }

    #[test]
    fn import_formats_start_with_detection() {
        let options = import_format_options();
        assert_eq!(options.len(), Format::ALL.len() + 1);
        assert_eq!(import_format_at(0), None);
        assert_eq!(import_format_at(1), Some(Format::ALL[0]));
        assert_eq!(import_format_at(99), None);
    }

    #[test]
    fn preview_and_summary_read_naturally() {
        assert_eq!(
            preview_text(&parsed(42, &["a", "b", "c", "d", "e"], 2)),
            "Found 42 items in 5 folders; 2 cannot be imported"
        );
        assert_eq!(
            preview_text(&parsed(1, &["a"], 0)),
            "Found 1 item in 1 folder"
        );
        let summary = ImportSummary {
            items: 42,
            skipped: 2,
            folders_created: 3,
            folders_reused: 2,
        };
        assert_eq!(
            summary_text(&summary),
            "Imported 42 items, and created 3 folders (reused 2); 2 could not be imported."
        );
        assert_eq!(
            summary_text(&ImportSummary {
                items: 1,
                ..Default::default()
            }),
            "Imported 1 item."
        );
    }

    #[test]
    fn target_folder_rewrites_the_import() {
        let mut p = parsed(2, &["a", "b"], 0);
        apply_target(&mut p, &Target::FileFolders);
        assert_eq!(p.folders.len(), 2);
        apply_target(&mut p, &Target::Folder("Old".into()));
        assert_eq!(p.folders, ["Old"]);
        assert!(p.items.iter().all(|i| i.folder == Some(0)));
        apply_target(&mut p, &Target::Nowhere);
        assert!(p.folders.is_empty() && p.items.iter().all(|i| i.folder.is_none()));
    }
}
