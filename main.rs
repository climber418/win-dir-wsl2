#![windows_subsystem = "windows"]


// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/UI/WindowsAndMessaging/fn.GetDesktopWindow.html
use log::{info, warn, error};
use log4rs;
use log4rs::{append::file::FileAppender, config::{Appender, Root}, encode::pattern::{PatternEncoder}, Config};

use std::ffi::c_void;
use std::ptr::{self};
use windows::core::w;
use windows::core::{IUnknown, Param, Interface, Result,PCWSTR};
use windows::Win32::{
    Foundation::{HWND, S_FALSE},
    System::{
        Com::{
            CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_LOCAL_SERVER,
            COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, 
        },
        Ole::{IEnumVARIANT},
        Variant::{VARIANT,VT_DISPATCH},
    },
    UI::Shell::{
        IPersistIDList, IShellBrowser, IShellItem, IShellWindows, IUnknown_QueryService,
        SHCreateItemFromIDList, SID_STopLevelBrowser, ShellWindows,
        SIGDN_DESKTOPABSOLUTEPARSING
    },
    UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK,GetForegroundWindow,GetWindowThreadProcessId}
};

// 获取explorer.exe里selected file的路径
fn get_location_from_view(browser: &IShellBrowser) -> Result<Vec<u16>> {
    let shell_view = unsafe { browser.QueryActiveShellView() }?;
    let persist_id_list: IPersistIDList = shell_view.cast()?;
    let id_list = unsafe { persist_id_list.GetIDList() }?;

    // let mut item = MaybeUninit::<IShellItem>::uninit();
    // unsafe { SHCreateItemFromIDList(id_list, &IShellItem::IID, addr_of_mut!(item) as _) }?;
    // let item = unsafe { item.assume_init() };
    let item: IShellItem = unsafe { SHCreateItemFromIDList(id_list) }?;

    let ptr = unsafe { item.GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING) }?;

    // Copy UTF-16 string to `Vec<u16>` (including NUL terminator)
    let mut path = Vec::new();
    let mut p = ptr.0 as *const u16;
    loop {
        let ch = unsafe { *p };
        path.push(ch);
        if ch == 0 {
            break;
        }
        p = unsafe { p.add(1) };
    }

    // Cleanup
    unsafe { 
        CoTaskMemFree(Some(ptr.0 as *mut c_void));
        CoTaskMemFree(Some(id_list as *const c_void));
    }

    Ok(path)
}

fn get_browser_info<'a, P>(unk: P, hwnd: &mut HWND) -> Result<Vec<u16>>
where P: Param<IUnknown>,
{
    let shell_browser: IShellBrowser =
        unsafe { IUnknown_QueryService(unk, &SID_STopLevelBrowser) }?;
    *hwnd = unsafe { shell_browser.GetWindow() }?;

    return get_location_from_view(&shell_browser)
}

fn dump_windows(windows: &IShellWindows) -> Result<()> {
    let unk_enum = unsafe { windows._NewEnum() }?;
    let enum_variant = unk_enum.cast::<IEnumVARIANT>()?;
    loop {
        let mut fetched = 0;
        let mut var: [VARIANT; 1] = [VARIANT::default(); 1];
        let hr = unsafe { enum_variant.Next(&mut var, &mut fetched) };
        // No more windows?
        if hr == S_FALSE || fetched == 0 {
            break;
        }
        // Not an IDispatch interface?
        if unsafe { var[0].Anonymous.Anonymous.vt } != VT_DISPATCH {
            continue;
        }

        // Get the information
        let mut hwnd = Default::default();
        let location = get_browser_info(
            unsafe {
                var[0].Anonymous.Anonymous.Anonymous.pdispVal.as_ref().unwrap()
            },
            &mut hwnd,
        )?;

        let is_active_hwnd = unsafe {
            let foreground_hwnd = GetForegroundWindow();
            let foreground_thread_id =  GetWindowThreadProcessId(foreground_hwnd, None);
            let explorer_thread_id =  GetWindowThreadProcessId(hwnd, None);

            // Convert UTF-16 to UTF-8 for display
            let location = String::from_utf16_lossy(&location);
            info!("Explorer location: \"{}\" {}", location, format!("hwnd: {hwnd:#?}; {foreground_hwnd:#?}"));

            foreground_thread_id == explorer_thread_id
        };

        if is_active_hwnd {
            unsafe {
                MessageBoxW(None, PCWSTR(location.as_ptr()), w!("Hello"), MB_ICONINFORMATION | MB_OK);
            }
        }
    }

    Ok(())
}


fn main() -> Result<()> {

    // Initialize logging from the configuration file
    // log4rs::init_file("d:\\myproject\\win-dir-wrapper\\log4rs.yml", Default::default()).unwrap();

    // Create a custom JSON encoder
    let json_encoder = Box::new(PatternEncoder::new("{d} [{l}] - {m}{n}"));

    // Create a file appender with the custom encoder
    let file_appender = FileAppender::builder()
        .encoder(json_encoder)
        .build("d:\\myproject\\win-dir-wrapper\\log.json")
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

    // 获取控制台窗口句柄
    // let console_window = unsafe { GetConsoleWindow() };
    // if console_window.0 != 0 {
    //	println!("HIddee");
    //    // 隐藏控制台窗口
    //    unsafe { ShowWindow(console_window, SW_HIDE); }
    //}

    // unsafe {
    // MessageBoxW(None, w!("Hello"), w!("World"), MB_ICONINFORMATION | MB_OK);
    // } 

    let _ = unsafe {
        CoInitializeEx(
            Some(ptr::null() as *const c_void),
            COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
        )
    };

    let windows: IShellWindows = unsafe { 
        CoCreateInstance(&ShellWindows, None, CLSCTX_LOCAL_SERVER) 
    }?;
    dump_windows(&windows)?;

    Ok(())
}
