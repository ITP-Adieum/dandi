mod commands;
mod error;
mod state;

use std::path::Path;

use tauri::{AppHandle, Emitter, Manager};

use crate::state::AppState;

const EVENT_OPEN_PATHS: &str = "dandi://open-paths";

fn extract_existing_paths<'a>(args: impl Iterator<Item = &'a str>) -> Vec<String> {
    args.filter(|arg| !arg.starts_with('-') && !arg.trim().is_empty())
        .filter(|arg| Path::new(arg).exists())
        .map(ToString::to_string)
        .collect()
}

fn dispatch_open_paths(app: &AppHandle, paths: Vec<String>) {
    if paths.is_empty() {
        return;
    }
    if let Some(state) = app.try_state::<AppState>() {
        state.push_pending_open_paths(paths.clone());
    }
    let _ = app.emit(EVENT_OPEN_PATHS, paths);
    focus_main_window(app);
}

fn focus_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default()
        .manage(AppState::new())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init());

    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            let paths = extract_existing_paths(argv.iter().skip(1).map(String::as_str));
            if !paths.is_empty() {
                dispatch_open_paths(app, paths);
            } else {
                focus_main_window(app);
            }
        }));
    }

    let app_result = builder
        .setup(|app| {
            let startup_args: Vec<String> = std::env::args().skip(1).collect();
            let paths = extract_existing_paths(startup_args.iter().map(String::as_str));
            if !paths.is_empty() {
                if let Some(state) = app.try_state::<AppState>() {
                    state.push_pending_open_paths(paths);
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::inspect_archive,
            commands::pack_archive,
            commands::unpack_archive,
            commands::fix_archive_encoding,
            commands::cancel_operation,
            commands::list_encodings,
            commands::classify_dropped_paths,
            commands::take_pending_open_paths,
            commands::default_output_path,
            commands::reveal_in_file_manager,
        ])
        .build(tauri::generate_context!());

    let app = match app_result {
        Ok(app) => app,
        Err(err) => {
            eprintln!("failed to build Dandi desktop application: {err}");
            std::process::exit(1);
        }
    };

    app.run(|app_handle, event| {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let tauri::RunEvent::Opened { urls } = event {
            let paths: Vec<String> = urls
                .into_iter()
                .filter_map(|u| u.to_file_path().ok())
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            dispatch_open_paths(app_handle, paths);
        }

        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let _ = (app_handle, event);
    });
}
