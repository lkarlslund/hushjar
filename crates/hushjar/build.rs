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
    println!("cargo:rerun-if-env-changed=HUSHJAR_VERSION");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    // The release identity (see hushjar_core::VERSION), and its number for
    // the numeric file version: 66 for r0066, 0 for a dev build.
    let version: String = std::env::var("HUSHJAR_VERSION")
        .unwrap_or_else(|_| "dev".into())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        .collect();
    let number: u16 = version
        .strip_prefix('r')
        .map(|r| {
            r.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0);
    // embed-resource puts OUT_DIR on the resource compiler's include path.
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(
        std::path::Path::new(&out_dir).join("hushjar_version.h"),
        format!("#define HUSHJAR_BUILD {number}\n#define HUSHJAR_VERSION \"{version}\"\n"),
    )
    .expect("write hushjar_version.h");
    embed_resource::compile("../../packaging/windows/hushjar.rc", embed_resource::NONE)
        .manifest_required()
        .expect("embed the Windows icon");
}
