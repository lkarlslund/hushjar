slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;
    window.set_version(env!("CARGO_PKG_VERSION").into());
    window.run()
}
