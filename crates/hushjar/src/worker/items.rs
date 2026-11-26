//! Item and folder actions on the account worker: archive, passkeys,
//! organisation moves, folder rename and delete, and attachments.

use std::io::Read;
use std::path::Path;

use hushjar_core::api::MAX_FILE_BYTES;
use hushjar_core::session::{Session, SessionError};
use hushjar_core::store::Store;
use zeroize::Zeroizing;

use super::{Command, Event, describe};

/// Runs one item or folder command. Other commands are ignored.
pub(super) fn run(
    session: Option<&mut Session>,
    store: &Store,
    emit: &dyn Fn(Event),
    command: Command,
) {
    let Some(s) = session else {
        emit(Event::ItemActionFailed {
            message: "Unlock the account first".into(),
        });
        return;
    };
    let result = match command {
        Command::Archive(id) => s.archive(store, &id).map(|()| "Archived"),
        Command::Unarchive(id) => s.unarchive(store, &id).map(|()| "Taken out of the archive"),
        Command::RemovePasskey { item, credential } => s
            .remove_passkey(store, &item, &credential)
            .map(|_| "Passkey removed"),
        Command::MoveToOrganization {
            item,
            organization,
            collections,
        } => s
            .move_to_organization(store, &item, &organization, &collections)
            .map(|_| "Moved to the organisation"),
        Command::SetCollections { item, collections } => s
            .set_collections(store, &item, &collections)
            .map(|_| "Collections saved"),
        Command::RenameFolder { id, name } => s
            .rename_folder(store, &id, &name)
            .map(|()| "Folder renamed"),
        Command::RenameFolderTree { old, new } => s
            .rename_folder_tree(store, &old, &new)
            .map(|_| "Folder renamed"),
        Command::DeleteFolder(id) => s.delete_folder(store, &id).map(|()| "Folder deleted"),
        Command::DeleteAttachment { item, attachment } => s
            .delete_attachment(store, &item, &attachment)
            .map(|()| "Attachment deleted"),
        Command::AddAttachment { item, path } => {
            add_attachment(s, store, &item, &path).map(|()| "Attachment added")
        }
        Command::DownloadAttachment {
            item,
            attachment,
            path,
            open,
        } => {
            emit(download(s, &item, &attachment, &path, open));
            return;
        }
        _ => return,
    };
    match result {
        Ok(message) => emit(Event::ItemActionDone {
            vault: s.vault.clone(),
            message: message.into(),
        }),
        Err(e) => emit_failure(emit, &e),
    }
}

fn emit_failure(emit: &dyn Fn(Event), error: &SessionError) {
    if matches!(error, SessionError::SignInRequired) {
        emit(Event::NeedsSignIn { two_factor: vec![] });
        emit(Event::ItemActionFailed {
            message: String::new(),
        });
    } else {
        emit(Event::ItemActionFailed {
            message: sentence(&describe(error)),
        });
    }
}

/// Starts a message with a capital letter; session errors are written to
/// follow a colon.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn download(s: &mut Session, item: &str, attachment: &str, path: &Path, open: bool) -> Event {
    let bytes = match s.download_attachment(item, attachment) {
        Ok(bytes) => bytes,
        Err(SessionError::SignInRequired) => return Event::NeedsSignIn { two_factor: vec![] },
        Err(e) => {
            return Event::ItemActionFailed {
                message: sentence(&describe(&e)),
            };
        }
    };
    match crate::exchange::write_private(path, &bytes) {
        Ok(()) => Event::AttachmentWritten {
            path: path.to_path_buf(),
            open,
        },
        Err(e) => Event::ItemActionFailed {
            message: format!("Could not write the file: {e}"),
        },
    }
}

/// Reads the chosen file (refusing ones over the server's limit before
/// reading them) and attaches it.
fn add_attachment(
    s: &mut Session,
    store: &Store,
    item: &str,
    path: &Path,
) -> Result<(), SessionError> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "attachment".into());
    let unreadable =
        |e: std::io::Error| SessionError::Invalid(format!("could not read the file: {e}"));
    let file = std::fs::File::open(path).map_err(unreadable)?;
    if file.metadata().map_err(unreadable)?.len() > MAX_FILE_BYTES as u64 {
        return Err(SessionError::FileTooLarge);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(SessionError::FileTooLarge);
    }
    s.add_attachment(store, item, &name, &bytes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_start_with_a_capital() {
        assert_eq!(
            sentence("this server does not support archiving"),
            "This server does not support archiving"
        );
        assert_eq!(sentence(""), "");
    }

    /// Runs the item commands through the worker's handler against a real
    /// Vaultwarden server. Runs only when HUSHJAR_INTEROP is set; the
    /// account is invented and lives only in the test server's memory.
    mod interop {
        use std::cell::RefCell;

        use hushjar_core::api::Server;
        use hushjar_core::crypto::{self, HashPurpose, Kdf, SymmetricKey};
        use hushjar_core::vault::{Item, ItemKind, Vault};
        use serde_json::json;

        use super::super::*;

        const PASSWORD: &str = "invented interop password";
        const KDF: Kdf = Kdf::Pbkdf2 {
            iterations: 600_000,
        };

        fn register(base: &str, email: &str) -> SymmetricKey {
            let master = crypto::master_key(PASSWORD, email, KDF).unwrap();
            let hash = crypto::password_hash(&master, PASSWORD, HashPurpose::Server);
            let user_key = SymmetricKey::generate();
            let body = json!({
                "email": email,
                "name": "Hushjar interop test",
                "masterPasswordHash": hash.as_str(),
                "key": crypto::stretch(&master).wrap_key(&user_key),
                "kdf": 0,
                "kdfIterations": 600_000,
            });
            let response = ureq::post(format!("{base}/identity/accounts/register"))
                .send_json(&body)
                .unwrap();
            assert_eq!(response.status().as_u16(), 200, "registration failed");
            user_key
        }

        /// What one command produced: the vault after it, or its message.
        enum Outcome {
            Done(Box<Vault>, String),
            Failed(String),
            Written(std::path::PathBuf, bool),
            Other,
        }

        fn run_one(s: &mut Session, store: &Store, command: Command) -> Outcome {
            let seen = RefCell::new(Vec::new());
            run(
                Some(s),
                store,
                &|event| seen.borrow_mut().push(event),
                command,
            );
            let mut events = seen.into_inner();
            assert_eq!(events.len(), 1, "one event per command");
            match events.remove(0) {
                Event::ItemActionDone { vault, message } => Outcome::Done(Box::new(vault), message),
                Event::ItemActionFailed { message } => Outcome::Failed(message),
                Event::AttachmentWritten { path, open } => Outcome::Written(path, open),
                _ => Outcome::Other,
            }
        }

        fn done(outcome: Outcome) -> Vault {
            match outcome {
                Outcome::Done(vault, message) => {
                    assert!(!message.is_empty(), "a done action says what it did");
                    *vault
                }
                Outcome::Failed(message) => panic!("failed: {message}"),
                _ => panic!("unexpected event"),
            }
        }

        #[test]
        fn item_commands_round_trip() {
            let Ok(base) = std::env::var("HUSHJAR_INTEROP") else {
                eprintln!("skipped: set HUSHJAR_INTEROP to a Vaultwarden test server");
                return;
            };
            let email = format!("items-{}@example.invalid", uuid::Uuid::new_v4().simple());
            register(&base, &email);
            let dir = std::env::temp_dir().join(format!("hushjar-items-{}", uuid::Uuid::new_v4()));
            let store = Store::open(dir.clone()).unwrap();
            let mut s = Session::sign_in(
                &store,
                Server::parse(&base).unwrap(),
                &email,
                PASSWORD,
                None,
                None,
            )
            .unwrap();

            // Folders: a nested tree is renamed as a whole, then one is deleted.
            let parent = s.create_folder(&store, "Parent").unwrap();
            let child = s.create_folder(&store, "Parent/Child").unwrap();
            let mut item = Item::new(ItemKind::Login, None, Some(parent.clone()));
            item.name = "Files".into();
            let item = s.save(&store, &item).unwrap();
            let vault = done(run_one(
                &mut s,
                &store,
                Command::RenameFolderTree {
                    old: "Parent".into(),
                    new: "Renamed".into(),
                },
            ));
            let mut names: Vec<&str> = vault.folders.iter().map(|f| f.name.as_str()).collect();
            names.sort();
            assert_eq!(names, ["Renamed", "Renamed/Child"]);
            let vault = done(run_one(&mut s, &store, Command::DeleteFolder(child)));
            assert_eq!(vault.folders.len(), 1);

            // Archive and back.
            let vault = done(run_one(&mut s, &store, Command::Archive(item.id.clone())));
            assert!(vault.item(&item.id).unwrap().archived);
            let vault = done(run_one(&mut s, &store, Command::Unarchive(item.id.clone())));
            assert!(!vault.item(&item.id).unwrap().archived);

            // Attachments: add from a file, download it, delete it.
            let source = dir.join("notes.txt");
            std::fs::write(&source, b"invented attachment contents").unwrap();
            let vault = done(run_one(
                &mut s,
                &store,
                Command::AddAttachment {
                    item: item.id.clone(),
                    path: source,
                },
            ));
            let files = &vault.item(&item.id).unwrap().attachments;
            assert_eq!(files.len(), 1);
            assert_eq!(files[0].file_name, "notes.txt");
            let attachment = files[0].id.clone();
            let target = dir.join("downloaded.txt");
            match run_one(
                &mut s,
                &store,
                Command::DownloadAttachment {
                    item: item.id.clone(),
                    attachment: attachment.clone(),
                    path: target.clone(),
                    open: true,
                },
            ) {
                Outcome::Written(path, open) => assert!(path == target && open),
                Outcome::Failed(message) => panic!("download failed: {message}"),
                _ => panic!("unexpected event"),
            }
            assert_eq!(
                std::fs::read(&target).unwrap(),
                b"invented attachment contents"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&target).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            let vault = done(run_one(
                &mut s,
                &store,
                Command::DeleteAttachment {
                    item: item.id.clone(),
                    attachment,
                },
            ));
            assert!(vault.item(&item.id).unwrap().attachments.is_empty());

            // A file that cannot be read is explained, not sent.
            match run_one(
                &mut s,
                &store,
                Command::AddAttachment {
                    item: item.id.clone(),
                    path: dir.join("missing.bin"),
                },
            ) {
                Outcome::Failed(message) => {
                    assert!(message.starts_with("Could not read the file"), "{message}")
                }
                _ => panic!("a missing file must fail"),
            }

            // Personal items have no collections to change.
            match run_one(
                &mut s,
                &store,
                Command::SetCollections {
                    item: item.id.clone(),
                    collections: vec!["none".into()],
                },
            ) {
                Outcome::Failed(message) => assert!(message.starts_with("This item is personal")),
                _ => panic!("setting collections on a personal item must fail"),
            }
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
