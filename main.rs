#![windows_subsystem = "windows"]

use log::{info, warn, error};
use log4rs;
use log4rs::{append::file::FileAppender, config::{Appender, Root}, encode::pattern::PatternEncoder, Config};

use windows::core::{Interface, Result, w, PWSTR,Error};
use windows::Win32::{
    System::{
        Com::{
            CoCreateInstance, CoInitializeEx, CLSCTX_LOCAL_SERVER,
            COINIT_APARTMENTTHREADED, IServiceProvider, IDispatch,
        },
        Variant::VARIANT,
        SystemServices::SFGAO_FILESYSTEM,
        Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_NAME_WIN32, Sleep},
    },
    UI::Shell::{
        IShellBrowser, IShellWindows, IShellView, IShellItem,
        ShellWindows, SIGDN_FILESYSPATH, SIGDN_DESKTOPABSOLUTEPARSING, SVGIO_SELECTION,
        IShellItemArray, SHGetKnownFolderPath, FOLDERID_Desktop, KNOWN_FOLDER_FLAG
    },
    UI::WindowsAndMessaging::{GetForegroundWindow, FindWindowExW,
         GetWindowThreadProcessId, GetWindowTextW, GetClassNameW},
};
use std::process::Command;
use std::env;

unsafe fn get_window_title(hwnd: windows::Win32::Foundation::HWND) -> String {
    let mut buffer: [u16; 512] = [0; 512];
    let length = GetWindowTextW(hwnd, &mut buffer);

    if length > 0 {
        String::from_utf16_lossy(&buffer[0..length as usize])
    } else {
        String::from("(No Title)")
    }
}

unsafe fn get_process_path_from_hwnd(hwnd: windows::Win32::Foundation::HWND) -> String {
    let mut process_id: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut process_id));

    if process_id == 0 {
        return String::from("Unknown");
    }

    let process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id);
    if let Ok(handle) = process_handle {
        let mut buffer: [u16; 1024] = [0; 1024];
        let mut size: u32 = buffer.len() as u32;
        let pwstr = PWSTR(buffer.as_mut_ptr());

        if QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, pwstr, &mut size).is_ok() {
            let path = String::from_utf16_lossy(&buffer[0..size as usize]);
            return path;
        }
    }

    String::from("Unknown")
}

unsafe fn get_selected_file_from_explorer() -> Result<String> {
	info!("get_selected_file_from_explorer -->");
    let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

    let mut foreground_hwnd = GetForegroundWindow();
    let foreground_exe = get_process_path_from_hwnd(foreground_hwnd);
    let foreground_title = get_window_title(foreground_hwnd);
    info!("Foreground window handle: {:?}, title: '{}', exe: {}", foreground_hwnd, foreground_title, foreground_exe);

    if !foreground_exe.to_lowercase().ends_with("\\explorer.exe") {
        Sleep(100);
        foreground_hwnd = GetForegroundWindow();
        let foreground_exe = get_process_path_from_hwnd(foreground_hwnd);
        let foreground_title = get_window_title(foreground_hwnd);
        info!("After sleep, foreground window handle: {:?}, title: '{}', exe: {}", foreground_hwnd, foreground_title, foreground_exe);

        if !foreground_exe.to_lowercase ().ends_with("\\explorer.exe") {
            return Result::Err(Error::from_win32());
        }
    }

    // Try to find ShellTabWindowClass child window
    let result_hwnd_result = FindWindowExW(Some(foreground_hwnd), None, w!("ShellTabWindowClass"), None);

    let mut target_path = String::new();

    let shell_windows: IShellWindows = CoCreateInstance(&ShellWindows, None, CLSCTX_LOCAL_SERVER)?;
    let count = shell_windows.Count().unwrap_or_default();
    info!("Shell windows count: {}", count);


    if let Ok(result_hwnd) = result_hwnd_result {
        // If we found ShellTabWindowClass, match against it
        info!("Found ShellTabWindowClass, matching shell windows against it");
        for i in 0..count {
            let dispatch: IDispatch = shell_windows.Item(&VARIANT::from(i))?;
            let shell_browser = dispath2browser(dispatch);

            if shell_browser.is_none() {
                info!("Shell browser {} is none, skipping", i);
                continue;
            }
            let shell_browser = shell_browser.unwrap();
            // 调用 GetWindow 可能会阻塞 GUI 消息
            let phwnd = shell_browser.GetWindow()?;
            let window_exe = get_process_path_from_hwnd(phwnd);
            let window_title = get_window_title(phwnd);
            info!("Shell window {} handle: {:?}, title: '{}', exe: {}", i, phwnd, window_title, window_exe);

            // Just match the foreground window directly
            if result_hwnd.0 != phwnd.0 && foreground_hwnd.0 != phwnd.0 {
                info!("Window {} doesn't match foreground, skipping", i);
                continue;
            }

            info!("Found matching window {}, getting active shell view", i);
            let shell_view = shell_browser.QueryActiveShellView().unwrap();
            target_path = get_base_location_from_shellview(shell_view); // get_selected_file_path_from_shellview(shell_view);
            info!("Got target path: {}", target_path);
            break;
        }
        info!("get_selected_file_from_explorer: <-- {}",target_path);
        return Ok(target_path);
    } else {
        // Check if foreground window is desktop window (Progman or WorkerW)
        let mut class_name = [0u16; 256];
        let len = GetClassNameW(foreground_hwnd, &mut class_name);
        if len > 0 {
            let class_str = String::from_utf16_lossy(&class_name[0..len as usize]);
            info!("Foreground window class name: {}", class_str);
            if class_str == "Progman" || class_str == "WorkerW" {
                info!("Foreground window is Desktop, returning desktop path");
                let desktop_path = SHGetKnownFolderPath(&FOLDERID_Desktop, KNOWN_FOLDER_FLAG(0), None)?.to_string()?;
                return Ok(desktop_path);
            }
        }
    }

    return Result::Err(Error::from_win32());
}

unsafe fn dispath2browser(dispatch: IDispatch) -> Option<IShellBrowser> {
    
    let mut service_provider: Option<IServiceProvider> = None;
    dispatch.query(
            &IServiceProvider::IID,
            &mut service_provider as *mut _ as *mut _,
        )
        .ok()
        .unwrap();
    if service_provider.is_none() {
		info!("dispath2browser: service_provider.is_none");
        return None;
    }
    let shell_browser = service_provider
        .unwrap()
        .QueryService::<IShellBrowser>(&IShellBrowser::IID)
        .ok();
    shell_browser
}

unsafe fn get_selected_file_path_from_shellview(shell_view: IShellView) -> String {
    let mut target_path = String::new();
    let shell_items = shell_view.GetItemObject::<IShellItemArray>(SVGIO_SELECTION);

    if shell_items.is_err() {
        return target_path;
    }
    info!("shell_items: {:?}", shell_items);
    let shell_items = shell_items.unwrap();
    let count = shell_items.GetCount().unwrap_or_default();
    for i in 0..count {
        let shell_item = shell_items.GetItemAt(i).unwrap();

        // 如果不是文件对象则继续循环
        if let Ok(attrs) = shell_item.GetAttributes(SFGAO_FILESYSTEM) {
            log::info!("attrs: {:?}", attrs);
            if attrs.0 == 0 {
                continue;
            }
        }

        if let Ok(display_name) = shell_item.GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING)
        {
            let tmp = display_name.to_string();
            if tmp.is_err() {
                continue;
            }
            target_path = tmp.unwrap();
            break;
        }

        if let Ok(display_name) = shell_item.GetDisplayName(SIGDN_FILESYSPATH) {
            info!("display_name: {:?}", display_name);
            let tmp = display_name.to_string();
            if tmp.is_err() {
                info!("display_name error: {:?}", tmp.err());
                continue;
            }
            target_path = tmp.unwrap();
            break;
        }
        
    }
    target_path
}

unsafe fn get_base_location_from_shellview(shell_view: IShellView) -> String {
	info!("get_base_location_from_shellview -->");
    let mut base_path = String::new();

    // Try to get the current folder from the shell view
    // We need to query for IFolderView interface to get folder information
    if let Ok(folder_view) = shell_view.cast::<windows::Win32::UI::Shell::IFolderView>() {
        info!("Successfully cast to IFolderView");
        if let Ok(folder) = folder_view.GetFolder::<IShellItem>() {
            info!("Successfully got folder IShellItem");
            // Try to get the file system path first
            if let Ok(display_name) = folder.GetDisplayName(SIGDN_FILESYSPATH) {
                if let Ok(path_str) = display_name.to_string() {
                    info!("Got FILESYSPATH: {}", path_str);
                    base_path = path_str;
                }
            }
            // Fallback to desktop absolute parsing name
            else if let Ok(display_name) = folder.GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING) {
                if let Ok(path_str) = display_name.to_string() {
                    info!("Got DESKTOPABSOLUTEPARSING: {}", path_str);
                    base_path = path_str;
                }
            } else {
                info!("Failed to get display name");
            }
        } else {
            info!("Failed to get folder from IFolderView");
        }
    } else {
        info!("Failed to cast to IFolderView");
    }
    info!("get_base_location_from_shellview <-- returning: {}", base_path);
    base_path
}

fn main() -> Result<()> {

    // Initialize logging from the configuration file
    // log4rs::init_file("d:\\myproject\\win-dir-wsl2\\log4rs.yml", Default::default()).unwrap();

    // Create a custom JSON encoder
    // let json_encoder = Box::new(PatternEncoder::new("{d} [{l}] - {m}{n}"));
    let json_encoder = Box::new(PatternEncoder::new("{m}{n}"));

    // Create a file appender with the custom encoder
    let file_appender = FileAppender::builder()
        .encoder(json_encoder)
        .build("d:\\myproject\\win-dir-wsl2\\logs\\log.txt")
        .unwrap();

    // Create a log configuration with the file appender
    let config = Config::builder()
        .appender(Appender::builder().build("file", Box::new(file_appender)))
        .build(Root::builder().appender("file").build(log::LevelFilter::Info))
        .unwrap();

    // Initialize the logger
    log4rs::init_config(config).unwrap();

    // Log some messages
    info!("This is an info message.");
    warn!("This is a warning message.");
    error!("This is an error message.");

    let result = unsafe { get_selected_file_from_explorer() };

    match result {
        Ok(path) => {
            info!("result is {:?} <-------------------", path);

            // Execute mintty with the selected path
            let userprofile = env::var("USERPROFILE").unwrap_or_else(|_| String::from("C:\\Users\\Default"));
            let executable = format!("{}\\AppData\\Local\\wsltty\\bin\\mintty.exe", userprofile);
            let configdir = format!("{}\\AppData\\Roaming\\wsltty", userprofile);

            info!("Executing: {} with path: {}", executable, path);

            let mut cmd = Command::new(&executable);
            cmd.arg("--WSL=")
               .arg(format!("--configdir={}", configdir))
               .arg("-");

            // Set working directory to the selected path
            cmd.current_dir(&path);

            // Spawn the process without waiting for it to finish
            match cmd.spawn() {
                Ok(child) => {
                    info!("Process spawned with PID: {:?}, working directory: {}", child.id(), path);
                }
                Err(e) => {
                    error!("Failed to spawn process: {:?}", e);
                }
            }
        }
        Err(e) => {
            // When error occurs, use home directory as fallback
            let userprofile = env::var("USERPROFILE").unwrap_or_else(|_| String::from("C:\\Users\\Default"));
            let executable = format!("{}\\AppData\\Local\\wsltty\\bin\\mintty.exe", userprofile);
            let configdir = format!("{}\\AppData\\Roaming\\wsltty", userprofile);

            info!("Not Found Explorer.exe Active Tab: {:?}. Using home directory: {}", e, userprofile);
            info!("Executing: {}", executable);

            let mut cmd = Command::new(&executable);
            cmd.arg("--WSL=")
               .arg(format!("--configdir={}", configdir))
               .arg("-~")
               .arg("-");

            // Set working directory to home directory
            cmd.current_dir(&userprofile);

            // Spawn the process without waiting for it to finish
            match cmd.spawn() {
                Ok(child) => {
                    info!("Process spawned with PID: {:?}, working directory: {}", child.id(), userprofile);
                }
                Err(e) => {
                    error!("Failed to spawn process: {:?}", e);
                }
            }
        }
    }
	info!("      ");
    Ok(())
}
