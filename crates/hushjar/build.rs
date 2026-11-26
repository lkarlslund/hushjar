fn main() {
    slint_build::compile("ui/app.slint").expect("compile Slint UI");
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
