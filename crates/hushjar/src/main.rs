slint::include_modules!();

mod app;
mod mock;
#[cfg(feature = "snapshot")]
mod snapshot;
mod tree;

fn main() -> Result<(), slint::PlatformError> {
    let app = app::App::new()?;

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

    app.window.run()
}
