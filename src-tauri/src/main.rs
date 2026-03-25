// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{Emitter, Manager, State};
use timenc::{encrypt, decrypt, generate_keyfile, EncryptOptions, DecryptOptions};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    input_path: PathBuf,
    output_path: PathBuf,
    password: String,
    keyfile_path: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptRequest {
    input_path: PathBuf,
    output_dir: PathBuf,
    password: String,
    keyfile_path: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperationResult {
    success: bool,
    message: String,
    path: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct LaunchContext {
    pending_open_file: Option<PathBuf>,
}

#[derive(Debug, Serialize, Clone)]
struct OpenFilePayload {
    path: PathBuf,
}

#[derive(Default)]
struct AppState {
    pending_open_file: Mutex<Option<PathBuf>>,
}

fn find_timenc_path<I>(args: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = OsString>,
{
    args.into_iter().find_map(|arg| {
        let path = PathBuf::from(arg);
        let is_timenc = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("timenc"))
            .unwrap_or(false);

        if is_timenc && path.is_file() {
            Some(path)
        } else {
            None
        }
    })
}

#[tauri::command]
async fn encrypt_file(request: EncryptRequest) -> Result<OperationResult, String> {
    let options = EncryptOptions {
        password: request.password,
        keyfile_path: request.keyfile_path,
        output_path: request.output_path,
    };

    match encrypt(&request.input_path, options) {
        Ok(path) => Ok(OperationResult {
            success: true,
            message: "File encrypted successfully".to_string(),
            path: Some(path),
        }),
        Err(e) => Ok(OperationResult {
            success: false,
            message: e.to_string(),
            path: None,
        }),
    }
}

#[tauri::command]
async fn decrypt_file(request: DecryptRequest) -> Result<OperationResult, String> {
    let options = DecryptOptions {
        password: request.password,
        keyfile_path: request.keyfile_path,
        output_dir: request.output_dir,
    };

    match decrypt(&request.input_path, options) {
        Ok(path) => Ok(OperationResult {
            success: true,
            message: "File decrypted successfully".to_string(),
            path: Some(path),
        }),
        Err(e) => Ok(OperationResult {
            success: false,
            message: e.to_string(),
            path: None,
        }),
    }
}

#[tauri::command]
async fn create_keyfile(output_path: PathBuf) -> Result<OperationResult, String> {
    match generate_keyfile(&output_path) {
        Ok(path) => Ok(OperationResult {
            success: true,
            message: "Keyfile created successfully".to_string(),
            path: Some(path),
        }),
        Err(e) => Ok(OperationResult {
            success: false,
            message: e.to_string(),
            path: None,
        }),
    }
}

#[tauri::command]
async fn get_launch_context(state: State<'_, AppState>) -> Result<LaunchContext, String> {
    let pending_open_file = state
        .pending_open_file
        .lock()
        .map_err(|_| "failed to access app state".to_string())?
        .clone();

    Ok(LaunchContext { pending_open_file })
}

fn main() {
    let initial_open_file = find_timenc_path(std::env::args_os().skip(1));

    tauri::Builder::default()
        .manage(AppState {
            pending_open_file: Mutex::new(initial_open_file),
        })
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if let Some(path) = find_timenc_path(argv.into_iter().map(OsString::from)) {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
                if let Some(state) = app.try_state::<AppState>() {
                    if let Ok(mut pending) = state.pending_open_file.lock() {
                        *pending = Some(path.clone());
                    }
                }
                let _ = app.emit("timenc://open-file", OpenFilePayload { path });
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            encrypt_file,
            decrypt_file,
            create_keyfile,
            get_launch_context
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
