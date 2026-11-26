//! Start on login.
//!
//! On Linux this writes an XDG autostart entry,
//! `$XDG_CONFIG_HOME/autostart/io.github.lkarlslund.Hushjar.desktop`, that
//! runs the current binary with [`HIDDEN_FLAG`] so Hushjar starts in the
//! tray. KDE Plasma, GNOME and most other desktops read this folder.
//!
//! Inside Flatpak the sandbox cannot write there; the Background portal is
//! the right route and is not implemented yet, so the calls return
//! [`Error::Unavailable`].

use super::Error;

/// The command-line flag that starts Hushjar without showing its window.
pub const HIDDEN_FLAG: &str = "--hidden";

/// Whether this process was started with [`HIDDEN_FLAG`], meaning it should
/// start in the tray instead of showing its window.
pub fn started_hidden() -> bool {
    std::env::args_os().skip(1).any(|arg| arg == HIDDEN_FLAG)
}

/// Whether Hushjar is set to start on login.
pub fn is_enabled() -> bool {
    imp::is_enabled()
}

/// Makes Hushjar start, hidden, on login. Replaces an existing entry, so
/// calling it again after the binary moved fixes the path.
pub fn enable() -> Result<(), Error> {
    imp::enable()
}

/// Stops Hushjar starting on login. Succeeds when it was not enabled.
pub fn disable() -> Result<(), Error> {
    imp::disable()
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Error, HIDDEN_FLAG};
    use crate::APP_ID;
    use std::path::{Path, PathBuf};

    pub fn is_enabled() -> bool {
        let Some(path) = entry_path() else {
            return false;
        };
        std::fs::read_to_string(path).is_ok_and(|contents| entry_enabled(&contents))
    }

    pub fn enable() -> Result<(), Error> {
        refuse_in_flatpak()?;
        let path = entry_path().ok_or_else(no_config_dir)?;
        let contents = desktop_entry(&program()?)?;
        let dir = path.parent().ok_or_else(no_config_dir)?;
        std::fs::create_dir_all(dir)?;
        // Write then rename, so a crash never leaves half an entry behind.
        let partial = path.with_extension("desktop.partial");
        std::fs::write(&partial, contents)?;
        std::fs::rename(&partial, &path)?;
        Ok(())
    }

    pub fn disable() -> Result<(), Error> {
        refuse_in_flatpak()?;
        let path = entry_path().ok_or_else(no_config_dir)?;
        match std::fs::remove_file(path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }

    fn refuse_in_flatpak() -> Result<(), Error> {
        if super::super::in_flatpak() {
            return Err(Error::Unavailable(
                "start on login inside Flatpak (needs the Background portal)".into(),
            ));
        }
        Ok(())
    }

    fn no_config_dir() -> Error {
        Error::Unavailable("a configuration folder (HOME is not set)".into())
    }

    /// Where the autostart entry lives for this user.
    fn entry_path() -> Option<PathBuf> {
        autostart_dir(
            std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
        )
        .map(|dir| dir.join(format!("{APP_ID}.desktop")))
    }

    /// `$XDG_CONFIG_HOME/autostart`, or `~/.config/autostart` when the
    /// variable is unset or not absolute, as the XDG base directory spec
    /// requires.
    pub(super) fn autostart_dir(
        config_home: Option<PathBuf>,
        home: Option<PathBuf>,
    ) -> Option<PathBuf> {
        let config = match config_home {
            Some(dir) if dir.is_absolute() => dir,
            _ => home.filter(|h| h.is_absolute())?.join(".config"),
        };
        Some(config.join("autostart"))
    }

    /// The binary to start: the AppImage when running from one (the
    /// extracted binary disappears after exit), else this executable.
    fn program() -> Result<PathBuf, Error> {
        if let Some(appimage) = std::env::var_os("APPIMAGE").filter(|p| !p.is_empty()) {
            return Ok(PathBuf::from(appimage));
        }
        Ok(std::env::current_exe()?)
    }

    /// The contents of the autostart entry that runs `program` hidden.
    pub(super) fn desktop_entry(program: &Path) -> Result<String, Error> {
        let program = program.to_str().ok_or_else(|| {
            Error::Unavailable("an autostart entry for a program path that is not UTF-8".into())
        })?;
        if program.contains(['\n', '\r']) {
            return Err(Error::Unavailable(
                "an autostart entry for a program path with a line break".into(),
            ));
        }
        Ok(format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Hushjar\n\
             Comment=Start Hushjar in the system tray\n\
             Exec={} {HIDDEN_FLAG}\n\
             Icon={APP_ID}\n\
             Terminal=false\n\
             X-GNOME-Autostart-enabled=true\n",
            exec_arg(program)
        ))
    }

    /// Characters that force quoting in an `Exec` argument (desktop entry
    /// spec, "The Exec key").
    const RESERVED: &[char] = &[
        ' ', '\t', '\n', '"', '\'', '\\', '>', '<', '~', '|', '&', ';', '$', '*', '?', '#', '(',
        ')', '`',
    ];

    /// Encodes one `Exec` argument: quoted when needed with `"`, `` ` ``,
    /// `$` and `\` escaped inside the quotes, `%` doubled so it is not read
    /// as a field code, and finally backslashes doubled again because the
    /// whole value is a desktop entry string.
    pub(super) fn exec_arg(arg: &str) -> String {
        let mut quoted = if arg.is_empty() || arg.contains(RESERVED) {
            let mut out = String::from('"');
            for c in arg.chars() {
                if matches!(c, '"' | '`' | '$' | '\\') {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
            out
        } else {
            arg.to_owned()
        };
        quoted = quoted.replace('%', "%%");
        quoted.replace('\\', "\\\\")
    }

    /// Whether an autostart entry is switched on: desktops skip entries
    /// marked `Hidden=true` or `X-GNOME-Autostart-enabled=false`, which is
    /// how their settings panels turn an entry off without deleting it.
    pub(super) fn entry_enabled(contents: &str) -> bool {
        let mut in_main_group = false;
        for line in contents.lines().map(str::trim) {
            if line.starts_with('[') {
                in_main_group = line == "[Desktop Entry]";
                continue;
            }
            if !in_main_group {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match (key.trim(), value.trim()) {
                ("Hidden", "true") | ("X-GNOME-Autostart-enabled", "false") => return false,
                _ => {}
            }
        }
        true
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::Error;

    pub fn is_enabled() -> bool {
        false
    }

    pub fn enable() -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    pub fn disable() -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::imp::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn autostart_dir_respects_xdg_config_home() {
        let home = Some(PathBuf::from("/home/u"));
        assert_eq!(
            autostart_dir(Some("/cfg".into()), home.clone()),
            Some(PathBuf::from("/cfg/autostart"))
        );
        assert_eq!(
            autostart_dir(None, home.clone()),
            Some(PathBuf::from("/home/u/.config/autostart"))
        );
        // A relative XDG_CONFIG_HOME is invalid and must be ignored.
        assert_eq!(
            autostart_dir(Some("cfg".into()), home),
            Some(PathBuf::from("/home/u/.config/autostart"))
        );
        assert_eq!(autostart_dir(None, None), None);
    }

    #[test]
    fn plain_paths_are_not_quoted() {
        assert_eq!(exec_arg("/usr/bin/hushjar"), "/usr/bin/hushjar");
    }

    #[test]
    fn exec_arguments_are_quoted_and_escaped() {
        assert_eq!(exec_arg("/opt/My Apps/hushjar"), "\"/opt/My Apps/hushjar\"");
        assert_eq!(exec_arg("/a/100%/b"), "/a/100%%/b");
        assert_eq!(exec_arg("/a/$x/b"), "\"/a/\\\\$x/b\"");
        // A backslash is escaped inside the quotes, then again as a string.
        assert_eq!(exec_arg("/a\\b"), "\"/a\\\\\\\\b\"");
        assert_eq!(exec_arg(""), "\"\"");
    }

    #[test]
    fn entry_runs_the_program_hidden() {
        let entry = desktop_entry(Path::new("/opt/hush jar/hushjar")).unwrap();
        assert!(entry.starts_with("[Desktop Entry]\n"));
        assert!(entry.contains("\nExec=\"/opt/hush jar/hushjar\" --hidden\n"));
        assert!(entry.contains("\nIcon=io.github.lkarlslund.Hushjar\n"));
        assert!(entry_enabled(&entry));
    }

    #[test]
    fn line_breaks_in_the_path_are_refused() {
        assert!(desktop_entry(Path::new("/a\nb")).is_err());
    }

    #[test]
    fn disabled_entries_are_recognised() {
        assert!(!entry_enabled("[Desktop Entry]\nHidden=true\n"));
        assert!(!entry_enabled(
            "[Desktop Entry]\nX-GNOME-Autostart-enabled=false\n"
        ));
        // Keys in other groups do not count.
        assert!(entry_enabled(
            "[Desktop Entry]\nExec=x\n[Desktop Action a]\nHidden=true\n"
        ));
    }
}
