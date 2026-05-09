//! Sovereign Vault desktop entry point.
//!
//! Boots a Tauri window that loads the Svelte UI bundle from `../../../ui/dist`
//! (or the Vite dev server during `cargo tauri dev`). Tauri commands proxy to
//! the `sv-core` integration crate.

#[tauri::command]
fn app_version() -> String {
    sv_core::version().to_string()
}

/// Build and run the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![app_version])
        .run(tauri::generate_context!())
        .expect("error while running Sovereign Vault");
}
