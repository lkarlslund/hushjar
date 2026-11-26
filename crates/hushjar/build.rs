fn main() {
    // Debug builds (and so tests) keep element names and labels in the
    // generated code, which the layout tests need to find buttons.
    let debug = std::env::var("PROFILE").as_deref() == Ok("debug");
    let config = slint_build::CompilerConfiguration::new().with_debug_info(debug);
    slint_build::compile_with_config("ui/app.slint", config).expect("compile Slint UI");
    embed_windows_resources();
}

/// Puts the icon and version details into hushjar.exe. The build script runs
/// on the build machine, so the target is read from Cargo's environment.
fn embed_windows_resources() {
    println!("cargo:rerun-if-changed=../../packaging/windows");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("../../packaging/windows/hushjar.rc", embed_resource::NONE)
            .manifest_required()
            .expect("embed the Windows icon");
    }
}
