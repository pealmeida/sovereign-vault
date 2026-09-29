fn main() {
    let mut attributes = tauri_build::Attributes::new();

    // Windows (MSVC): embed the Common Controls v6 manifest through the
    // LINKER so it reaches every link target — the app binary AND the lib
    // test harness. tauri-build only attaches it as a resource to the app
    // binary; the dialog plugin imports comctl32!TaskDialogIndirect (v6-only),
    // so a test exe without the manifest fails to load with
    // STATUS_ENTRYPOINT_NOT_FOUND (0xc0000139). tauri-build's own manifest is
    // switched off so the app still carries exactly one (tauri-apps
    // discussion #11179).
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        attributes = attributes
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
        let manifest = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }

    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}
