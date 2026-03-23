// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use timenc::{encrypt, decrypt, generate_keyfile, EncryptOptions, DecryptOptions};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    input_path: PathBuf,
    output_path: PathBuf,
    password: String,
    keyfile_path: Option<PathBuf>,
    delete_source: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptRequest {
    input_path: PathBuf,
    output_dir: PathBuf,
    password: String,
    keyfile_path: Option<PathBuf>,
    delete_source: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperationResult {
    success: bool,
    message: String,
    path: Option<PathBuf>,
}

#[tauri::command]
async fn encrypt_file(request: EncryptRequest) -> Result<OperationResult, String> {
    let options = EncryptOptions {
        password: request.password,
        keyfile_path: request.keyfile_path,
        output_path: request.output_path,
        delete_source: request.delete_source,
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
        delete_source: request.delete_source,
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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            encrypt_file,
            decrypt_file,
            create_keyfile
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
