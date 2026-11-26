//! File dialogs. The desktop uses the system's dialogs through rfd; Android
//! has no dialog backend yet, so the UI hides the buttons that need one
//! (see [`AVAILABLE`]) and these functions return `None` there.

use std::path::PathBuf;

/// Whether this platform has file dialogs.
pub const AVAILABLE: bool = cfg!(not(target_os = "android"));

/// A filter for the dialog: its name and the file extensions it shows.
pub type Filter<'a> = (&'a str, &'a [&'a str]);

/// Asks for an existing file to open. `None` if cancelled. Blocks, so call
/// it from a background thread.
pub fn pick_file(title: &str, filters: &[Filter<'_>]) -> Option<PathBuf> {
    #[cfg(not(target_os = "android"))]
    {
        let mut dialog = rfd::FileDialog::new().set_title(title);
        for (name, extensions) in filters {
            dialog = dialog.add_filter(*name, extensions);
        }
        dialog.pick_file()
    }
    #[cfg(target_os = "android")]
    {
        let _ = (title, filters);
        None
    }
}

/// Asks where to save a file, suggesting `file_name`. `None` if cancelled.
/// Blocks, so call it from a background thread.
pub fn save_file(title: &str, file_name: &str, filter: Filter<'_>) -> Option<PathBuf> {
    #[cfg(not(target_os = "android"))]
    {
        rfd::FileDialog::new()
            .set_title(title)
            .set_file_name(file_name)
            .add_filter(filter.0, filter.1)
            .save_file()
    }
    #[cfg(target_os = "android")]
    {
        let _ = (title, file_name, filter);
        None
    }
}
