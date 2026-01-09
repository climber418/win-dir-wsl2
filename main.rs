#![windows_subsystem = "windows"]

use log::{info, warn, error};
use log4rs;
use log4rs::{append::file::FileAppender, config::{Appender, Root}, encode::pattern::PatternEncoder, Config};

use windows::core::{Interface, Result, w};
use windows::Win32::{
    System::{
        Com::{
            CoCreateInstance, CoInitializeEx, CLSCTX_LOCAL_SERVER,
            COINIT_APARTMENTTHREADED, IServiceProvider,
        },
        Variant::VARIANT,
        SystemServices::SFGAO_FILESYSTEM,
    },
    UI::Shell::{
        IShellBrowser, IShellWindows, IShellView, IShellItem, IFolderView,
        ShellWindows, SIGDN_FILESYSPATH, SIGDN_DESKTOPABSOLUTEPARSING, SVGIO_SELECTION,
        IShellItemArray
    },
    UI::WindowsAndMessaging::{GetForegroundWindow, FindWindowExW, MessageBoxW, MB_ICONINFORMATION, MB_OK},
};
use windows::core::PCWSTR;
use windows::Win32::System::Com::IDispatch;


unsafe fn get_selected_file_from_explorer() -> Result<String> {
    let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

    let hwnd_gfw = GetForegroundWindow();
    let shell_windows: IShellWindows =
        CoCreateInstance(&ShellWindows, None, CLSCTX_LOCAL_SERVER)?;
    let result_hwnd = FindWindowExW(Some(hwnd_gfw), None, w!("ShellTabWindowClass"), None)?;

    let mut target_path = String::new();
    let count = shell_windows.Count().unwrap_or_default();

    for i in 0..count {
        let variant = VARIANT::from(i);
        let dispatch: IDispatch = shell_windows.Item(&variant)?;

        let shell_browser = dispath2browser(dispatch);

        if shell_browser.is_none() {
            continue;
        }
        let shell_browser = shell_browser.unwrap();
        // 调用 GetWindow 可能会阻塞 GUI 消息
        let phwnd = shell_browser.GetWindow()?;
        if hwnd_gfw.0 != phwnd.0 && result_hwnd.0 != phwnd.0 {
            continue;
        }

        let shell_view = shell_browser.QueryActiveShellView().unwrap();
        target_path = get_base_location_from_shellview(shell_view); // get_selected_file_path_from_shellview(shell_view);
    }
    info!("get_selected_file_from_explorer: {}",target_path);
    Ok(target_path)
}

unsafe fn dispath2browser(dispatch: IDispatch) -> Option<IShellBrowser> {
    
    let mut service_provider: Option<IServiceProvider> = None;
    dispatch
        .query(
            &IServiceProvider::IID,
            &mut service_provider as *mut _ as *mut _,
        )
        .ok()
        .unwrap();
    if service_provider.is_none() {
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
            println!("display_name: {:?}", display_name);
            let tmp = display_name.to_string();
            if tmp.is_err() {
                println!("display_name error: {:?}", tmp.err());
                continue;
            }
            target_path = tmp.unwrap();
            break;
        }
        
    }
    target_path
}

unsafe fn get_base_location_from_shellview(shell_view: IShellView) -> String {
    let mut base_path = String::new();
    
    // Try to get the current folder from the shell view
    // We need to query for IFolderView interface to get folder information
    if let Ok(folder_view) = shell_view.cast::<windows::Win32::UI::Shell::IFolderView>() {
        if let Ok(folder) = folder_view.GetFolder::<IShellItem>() {
            // Try to get the file system path first
            if let Ok(display_name) = folder.GetDisplayName(SIGDN_FILESYSPATH) {
                if let Ok(path_str) = display_name.to_string() {
                    base_path = path_str;
                }
            }
            // Fallback to desktop absolute parsing name
            else if let Ok(display_name) = folder.GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING) {
                if let Ok(path_str) = display_name.to_string() {
                    base_path = path_str;
                }
            }
        }
    }
    
    base_path
}

fn main() -> Result<()> {

    // Initialize logging from the configuration file
    // log4rs::init_file("d:\\myproject\\win-dir-forwarder\\log4rs.yml", Default::default()).unwrap();

    // Create a custom JSON encoder
    let json_encoder = Box::new(PatternEncoder::new("{d} [{l}] - {m}{n}"));

    // Create a file appender with the custom encoder
    let file_appender = FileAppender::builder()
        .encoder(json_encoder)
        .build("d:\\myproject\\win-dir-forwarder\\logs\\log.json")
        .unwrap();

    // Create a log configuration with the file appender
    let config = Config::builder()
        .appender(Appender::builder().build("file", Box::new(file_appender)))
        .build(Root::builder().appender("file").build(log::LevelFilter::Info))
        .unwrap();

    // Initialize the logger
    log4rs::init_config(config).unwrap();

    // Log some messages
    info!("This is an info message.-------------->");
    warn!("This is a warning message.");
    error!("This is an error message.");


    let result = unsafe { get_selected_file_from_explorer() };
    match result {
        Ok(path) => {
            info!("result is {:?} <-------------------", path);
            let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe {
                MessageBoxW(None, PCWSTR(wide_path.as_ptr()), w!("Selected File"), MB_ICONINFORMATION | MB_OK);
            }
        }
        Err(e) => {
            error!("Error getting selected file: {:?}", e);
        }
    }
    Ok(())
}
