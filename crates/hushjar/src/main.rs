slint::include_modules!();

mod app;
mod clipboard;
#[cfg(test)]
mod mock;
mod model;
#[cfg(feature = "snapshot")]
mod snapshot;
mod tree;
mod worker;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = match std::env::var_os("HUSHJAR_DATA_DIR") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => hushjar_core::store::default_root().ok_or("no home folder to keep data in")?,
    };
    let store = hushjar_core::store::Store::open(root)?;
    let app = app::App::new(store)?;

    match std::env::var("HUSHJAR_COLOR_SCHEME").as_deref() {
        Ok("light") => app
            .window
            .global::<Palette>()
            .set_color_scheme(slint::language::ColorScheme::Light),
        Ok("dark") => app
            .window
            .global::<Palette>()
            .set_color_scheme(slint::language::ColorScheme::Dark),
        _ => {}
    }

    #[cfg(feature = "snapshot")]
    let _snapshots =
        std::env::var_os("HUSHJAR_SNAPSHOT_DIR").map(|dir| snapshot::run(&app.window, dir.into()));

    app.window.run()?;
    Ok(())
}
