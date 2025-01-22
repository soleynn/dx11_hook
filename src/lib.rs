/*!
# Direct3D Overlay Injector

This dll implements an overlay system by injecting into a Direct3D 11 application. It hooks the `Present` function of the `IDXGISwapChain` interface to render a custom overlay on top of the target application's graphics. The primary functionalities and components of this module include:
Note this is my first time creating something like this, and it's highly experimental and there's a lot of things that can probably be improved upon.


## Key Features

- **Function Hooking**: 
  - Hooks the `Present` method of Direct3D's swap chain to intercept rendering calls.
  - Replaces the original `Present` function with a custom `hooked_present` to inject overlay rendering.

- **Overlay Window Creation**:
  - Registers a custom window class and creates a transparent, layered, and topmost window using the Windows API.
  - Implements window procedures to handle messages such as mouse events for dragging the overlay.

- **Direct3D Initialization**:
  - Sets up Direct3D 11 device, device context, swap chain, and render target view necessary for rendering the overlay.
  - Configures swap chain descriptors to match the target application's rendering parameters.

- **Rendering Loop**:
  - Implements a rendering loop that clears the render target with a semi-transparent color and presents the frame.
  - Ensures continuous rendering of the overlay by repeatedly calling `Present`.

- **Thread Management and Synchronization**:
  - Utilizes `OnceLock`, `Mutex`, and `Condvar` for thread-safe initialization and state management of the overlay.
  - Spawns a dedicated thread for initializing and running the overlay to avoid blocking the main application thread.

- **User Interaction Handling**:
  - Handles mouse events (`WM_LBUTTONDOWN`, `WM_MOUSEMOVE`, `WM_LBUTTONUP`) to allow users to drag the overlay window.
  - Updates the window position based on mouse movements when dragging is active.

- **Logging**:
  - Implements a logging mechanism that writes debug and error messages to `C:\testing\log.txt`.
  - Facilitates debugging by recording the flow of execution and any encountered issues.

- **DLL Entry Point (`DllMain`)**:
  - Initializes the hooking process when the DLL is loaded into the target application's process.
  - Starts the overlay initialization in a separate thread upon DLL attachment.

## Structure Overview

- **Imports**: 
  - Utilizes various Windows API modules for window management, Direct3D rendering, memory manipulation, and synchronization primitives.

- **Data Structures**:
  - `D3DResources`: Holds Direct3D device, context, swap chain, and render target view.
  - `OverlayState`: Maintains the state of the overlay, including initialization status and dragging state.
  - `SyncPtr`: A thread-safe pointer wrapper for storing the original `Present` function address.

- **Core Functions**:
  - `write_log`: Handles logging of messages to a file for debugging purposes. Will be deprecated later
  - `hooked_present`: The custom `Present` function that initializes the overlay and delegates to the original `Present`.
  - `run_overlay_init_and_loop`: Initializes the overlay resources and enters the message loop for the overlay window.
  - `window_proc`: Processes window messages for handling events like destruction and mouse interactions.
  - `register_window_class` & `create_overlay_window`: Handle the registration and creation of the overlay window.
  - `initialize_d3d`: Sets up Direct3D 11 resources required for rendering the overlay.
  - `hook_swapchain_present`: Performs the actual hooking of the `Present` function in the swap chain's vtable.
  - `render_overlay`: Executes the rendering logic for the overlay each frame.

## Usage

This module is intended to be compiled as a DLL and injected into a Direct3D 11 application's process. Upon injection, it sets up the necessary hooks and renders a semi-transparent overlay window that can be interacted with (e.g., dragged using the mouse). Logging is performed to assist with monitoring the overlay's behavior and diagnosing issues.

*/
use std::mem::size_of;
use std::ptr::null_mut;
use std::sync::{Condvar, Mutex, OnceLock};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::SystemTime;

use windows::core::{Interface, PCWSTR, Result as WinResult, w};
use windows::Win32::Foundation::{COLORREF, HMODULE, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Gdi::{HBRUSH, UpdateWindow};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
use windows::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, LoadCursorW, MoveWindow, PeekMessageW,
    PostQuitMessage, RegisterClassExW, SetLayeredWindowAttributes, ShowWindow, TranslateMessage,
    CS_HREDRAW, CS_VREDRAW, IDC_ARROW, LWA_ALPHA, MSG, PM_REMOVE, SW_SHOW, WM_DESTROY, WM_LBUTTONDOWN,
    WM_LBUTTONUP, WM_MOUSEMOVE, WNDCLASS_STYLES, WNDCLASSEXW, WS_EX_LAYERED, WS_EX_TOPMOST,
    WS_POPUP,
};

/// Writes a log message to a file at `C:\testing\log.txt`.
///
/// This function is used for debugging purposes and helps track the execution flow
/// and any potential issues during the overlay initialization and rendering process.
///
/// # Arguments
///
/// * `message` - A string slice containing the log message to be written
///
/// # Remarks
///
/// - Creates the `C:\testing` directory if it doesn't exist
/// - Appends the log message with a timestamp
/// - Silently fails if directory creation or file writing encounters issues
fn write_log(message: &str) { // implement ipc connection to exe later to get actual logs in console
    if let Err(_e) = std::fs::create_dir_all(r"C:\testing") {
        // well fuck ?
        // this only works if you pre make the directory in C:\ because of permission issues.
        return;
    }

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\testing\log.txt")
    {
        let timestamp = SystemTime::now();
        let _ = writeln!(file, "{:?}: {}", timestamp, message);
    }
}

type PresentFn = unsafe extern "C" fn(*mut IDXGISwapChain, u32, u32) -> u32;

struct D3DResources {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    swap_chain: IDXGISwapChain,
    render_target_view: ID3D11RenderTargetView,
}

#[derive(Default)]
struct OverlayState {
    initialized: bool,
    d3d_resources: Option<D3DResources>,
    is_dragging: bool,
    last_mouse_pos: POINT,
}

static OVERLAY_MANAGER: OnceLock<Mutex<OverlayState>> = OnceLock::new();

static OVERLAY_INITIALIZED_CONDVAR: OnceLock<Condvar> = OnceLock::new();

static INIT_THREAD_SPAWNED: OnceLock<()> = OnceLock::new();

#[derive(Clone, Copy)]
struct SyncPtr(*const core::ffi::c_void);
unsafe impl Send for SyncPtr {}
unsafe impl Sync for SyncPtr {}

static ORIGINAL_PRESENT_PTR: OnceLock<SyncPtr> = OnceLock::new();

/// A hooked implementation of the `Present` method for IDXGISwapChain.
///
/// This function intercepts the original `Present` call and performs the following tasks:
/// - Ensures the overlay initialization thread is spawned only once
/// - Calls the original `Present` method to maintain the original rendering behavior
///
/// # Safety
///
/// This is an unsafe extern "C" function that directly manipulates function pointers
/// and requires careful management of the original `Present` function.
///
/// # Returns
///
/// Returns the result of the original `Present` method call
unsafe extern "C" fn hooked_present(
    swap_chain: *mut IDXGISwapChain,
    sync_interval: u32,
    flags: u32,
) -> u32 {
    INIT_THREAD_SPAWNED.get_or_init(|| {
        write_log("Spawning overlay initialization thread");
        std::thread::spawn(|| {
            if let Err(e) = run_overlay_init_and_loop() {
                write_log(&format!("Overlay initialization error: {:?}", e));
            } else {
                write_log("Overlay initialization and loop completed successfully");
            }
        });
    });

    if let Some(ptr) = ORIGINAL_PRESENT_PTR.get() {
        let original: PresentFn = std::mem::transmute(ptr.0);
        return original(swap_chain, sync_interval, flags);
    }

    write_log("Original Present pointer not found, returning 0");
    0
}

/// Initializes and runs the overlay window and rendering loop.
///
/// This function performs several tasks:
/// - Obtains the module instance handle
/// - Registers a custom window class
/// - Creates an overlay window
/// - Initializes Direct3D resources
/// - Sets up the overlay manager state
/// - Enters a message loop for window event processing
///
/// # Returns
///
/// A `WinResult` indicating successful initialization and loop execution or an error
///
/// # Errors
///
/// Returns an error if any of the following fail:
/// - Getting module handle
/// - Registering window class
/// - Creating overlay window
/// - Initializing Direct3D resources
fn run_overlay_init_and_loop() -> WinResult<()> {
    write_log("run_overlay_init_and_loop started");
    let overlay_manager = OVERLAY_MANAGER.get_or_init(|| Mutex::new(OverlayState::default()));
    let condvar = OVERLAY_INITIALIZED_CONDVAR.get_or_init(Condvar::new);

    let hinstance = unsafe {
        match GetModuleHandleW(PCWSTR::null()) {
            Ok(handle) => handle,
            Err(e) => {
                write_log(&format!("GetModuleHandleW failed: {:?}", e));
                return Err(e);
            }
        }
    };
    write_log("Obtained HINSTANCE");

    if let Err(e) = register_window_class(hinstance.into()) {
        write_log(&format!("Failed to register window class: {:?}", e));
        return Err(e);
    }
    write_log("Window class registered successfully");

    let hwnd = match create_overlay_window(hinstance.into()) {
        Ok(h) => {
            write_log("Overlay window created successfully");
            h
        }
        Err(e) => {
            write_log(&format!("Failed to create overlay window: {:?}", e));
            return Err(e);
        }
    };

    let d3d_resources = match initialize_d3d(hwnd) {
        Ok(resources) => {
            write_log("D3D initialized successfully");
            resources
        }
        Err(e) => {
            write_log(&format!("Failed to initialize D3D: {:?}", e));
            return Err(e);
        }
    };

    {
        let mut manager = overlay_manager.lock().unwrap();
        manager.d3d_resources = Some(d3d_resources);
        manager.initialized = true;
        manager.is_dragging = false;
        manager.last_mouse_pos = POINT { x: 0, y: 0 };
        condvar.notify_all();
        write_log("Overlay manager state updated and condition variable notified");
    }

    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = UpdateWindow(hwnd);
    }
    write_log("Overlay window shown and updated");

    let mut msg = MSG::default();
    loop {
        unsafe {
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).into() {
                write_log(&format!("Processing message: {}", msg.message));
                if msg.message == WM_DESTROY {
                    write_log("WM_DESTROY received, posting quit message");
                    PostQuitMessage(0);
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        if msg.message == 18 /* WM_QUIT */ {
            write_log("WM_QUIT received, exiting message loop");
            break;
        }

        render_overlay();
    }

    write_log("run_overlay_init_and_loop completed successfully");
    Ok(())
}

/// Window procedure for handling overlay window messages and interactions.
///
/// Handles the following window messages:
/// - `WM_DESTROY`: Closes the window and posts a quit message
/// - `WM_LBUTTONDOWN`: Initiates window dragging
/// - `WM_MOUSEMOVE`: Updates window position during dragging
/// - `WM_LBUTTONUP`: Stops window dragging
///
/// # Safety
///
/// This is an unsafe extern "system" function that directly handles Windows messaging
///
/// # Arguments
///
/// * `hwnd` - Handle to the window
/// * `msg` - The window message
/// * `w_param` - Additional message information
/// * `l_param` - Additional message information
///
/// # Returns
///
/// A `LRESULT` indicating the result of message processing
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    write_log(&format!("window_proc called with msg: {}", msg));

    match msg {
        WM_DESTROY => {
            write_log("window_proc handling WM_DESTROY");
            PostQuitMessage(0);
            LRESULT(0)
        }
        WM_LBUTTONDOWN => {
            write_log("window_proc handling WM_LBUTTONDOWN");
            if let Some(overlay_manager) = OVERLAY_MANAGER.get() {
                let mut manager = overlay_manager.lock().unwrap();
                manager.is_dragging = true;
                SetCapture(hwnd);
                manager.last_mouse_pos = POINT {
                    x: ((l_param.0 & 0xFFFF) as i32),
                    y: (((l_param.0 >> 16) & 0xFFFF) as i32),
                };
                write_log(&format!(
                    "Started dragging at position: ({}, {})",
                    manager.last_mouse_pos.x, manager.last_mouse_pos.y
                ));
            }
            LRESULT(0)
        }
        WM_MOUSEMOVE => {
            if let Some(overlay_manager) = OVERLAY_MANAGER.get() {
                let mut manager = overlay_manager.lock().unwrap();
                if manager.is_dragging {
                    let current_pos = POINT {
                        x: ((l_param.0 & 0xFFFF) as i32),
                        y: (((l_param.0 >> 16) & 0xFFFF) as i32),
                    };
                    let dx = current_pos.x - manager.last_mouse_pos.x;
                    let dy = current_pos.y - manager.last_mouse_pos.y;

                    let mut rect = RECT::default();
                    let _ = windows::Win32::UI::WindowsAndMessaging::GetWindowRect(hwnd, &mut rect);

                    let _ = MoveWindow(
                        hwnd,
                        rect.left + dx,
                        rect.top + dy,
                        rect.right - rect.left,
                        rect.bottom - rect.top,
                        true,
                    );

                    manager.last_mouse_pos = current_pos;
                }
            }
            LRESULT(0)
        },
        WM_LBUTTONUP => {
            write_log("window_proc handling WM_LBUTTONUP");
            if let Some(overlay_manager) = OVERLAY_MANAGER.get() {
                let mut manager = overlay_manager.lock().unwrap();
                manager.is_dragging = false;
            }
            let _ = ReleaseCapture();
            write_log("Stopped dragging");
            LRESULT(0)
        }
        _ => {
            DefWindowProcW(hwnd, msg, w_param, l_param)
        }
    }
}

/// Registers a custom window class for the overlay window.
///
/// This function sets up the window class characteristics, including:
/// - Window procedure
/// - Cursor style
/// - Class name
/// - Window styles (CS_HREDRAW and CS_VREDRAW)
///
/// # Arguments
///
/// * `hinstance` - The module instance handle
///
/// # Returns
///
/// A `WinResult` indicating successful window class registration
///
/// # Errors
///
/// Returns an error if window class registration fails
fn register_window_class(hinstance: HINSTANCE) -> WinResult<()> {
    write_log("register_window_class called");

    let class_name = PCWSTR::from_raw(w!("MyOverlayWindowClass").as_ptr());
    let wnd_class = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        style: WNDCLASS_STYLES(CS_HREDRAW.0 | CS_VREDRAW.0),
        lpfnWndProc: Some(window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: Default::default(),
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW)? },
        hbrBackground: HBRUSH(null_mut()),
        lpszMenuName: PCWSTR::null(),
        lpszClassName: class_name,
        hIconSm: Default::default(),
    };

    unsafe {
        let atom = RegisterClassExW(&wnd_class);
        if atom == 0 {
            let error = windows::core::Error::from_win32();
            write_log(&format!("RegisterClassExW failed: {:?}", error));
            return Ok(());
        }
    }

    write_log("RegisterClassExW succeeded");
    Ok(())
}

/// Creates a transparent, topmost overlay window.
///
/// Configures the window with the following properties:
/// - Extended styles: Topmost and layered
/// - Window style: Popup
/// - Initial position and size
/// - Transparency and alpha blending
///
/// # Arguments
///
/// * `hinstance` - The module instance handle
///
/// # Returns
///
/// A `WinResult` containing the handle to the created window
///
/// # Errors
///
/// Returns an error if window creation or attribute setting fails
fn create_overlay_window(hinstance: HINSTANCE) -> WinResult<HWND> {
    write_log("create_overlay_window called");

    let class_name = PCWSTR::from_raw(w!("MyOverlayWindowClass").as_ptr());

    let ex_style = WS_EX_TOPMOST | WS_EX_LAYERED;

    let hwnd = unsafe {
        CreateWindowExW(
            ex_style,
            class_name,
            PCWSTR::from_raw(w!("Overlay Window").as_ptr()),
            WS_POPUP,
            100,    // X
            100,    // Y
            800,  // Width
            600,  // Height
            None,
            None,
            Some(hinstance),
            None,
        )
    };

    let hwnd = match hwnd {
        Ok(h) => {
            write_log("CreateWindowExW succeeded");
            h
        }
        Err(e) => {
            write_log(&format!("CreateWindowExW failed: {:?}", e));
            return Err(e);
        }
    };

    unsafe {
        if let Err(e) = SetLayeredWindowAttributes(hwnd, COLORREF(0), 150, LWA_ALPHA) {
            write_log(&format!("SetLayeredWindowAttributes failed: {:?}", e));
            return Err(e);
        }
        let _ = UpdateWindow(hwnd);
    }

    write_log("Overlay window attributes set successfully");
    Ok(hwnd)
}

/// Initializes Direct3D 11 resources for overlay rendering.
///
/// Performs the following setup:
/// - Creates a device, device context, and swap chain
/// - Configures swap chain descriptor
/// - Creates render target view
/// - Sets render targets
///
/// # Arguments
///
/// * `hwnd` - Window handle for the swap chain
///
/// # Returns
///
/// A `WinResult` containing the initialized Direct3D resources
///
/// # Errors
///
/// Returns an error if any Direct3D initialization steps fail
fn initialize_d3d(hwnd: HWND) -> WinResult<D3DResources> {
    write_log("initialize_d3d called");

    let swap_chain_desc = DXGI_SWAP_CHAIN_DESC {
        BufferDesc: DXGI_MODE_DESC {
            Width: 800,
            Height: 600,
            RefreshRate: DXGI_RATIONAL {
                Numerator: 60,
                Denominator: 1,
            },
            Format: DXGI_FORMAT_R8G8B8A8_UNORM,
            ScanlineOrdering: DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED,
            Scaling: DXGI_MODE_SCALING_UNSPECIFIED,
        },
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
        BufferCount: 1,
        OutputWindow: hwnd,
        Windowed: true.into(),
        SwapEffect: DXGI_SWAP_EFFECT_DISCARD,
        Flags: 0,
    };

    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;
    let mut swap_chain: Option<IDXGISwapChain> = None;

    unsafe {
        D3D11CreateDeviceAndSwapChain(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            HMODULE(null_mut()),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&swap_chain_desc),
            Some(&mut swap_chain),
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .map_err(|e| {
            write_log(&format!("D3D11CreateDeviceAndSwapChain failed: {:?}", e));
            windows::core::Error::new(e.code(), "Failed to create D3D11 device")
        })?;
    }

    let device = device.ok_or_else(|| {
        let error = windows::core::Error::new(
            windows::core::Error::from_win32().into(),
            "Device is None",
        );
        write_log("D3D device is None");
        error
    })?;
    let context = context.ok_or_else(|| {
        let error = windows::core::Error::new(
            windows::core::Error::from_win32().into(),
            "Context is None",
        );
        write_log("D3D context is None");
        error
    })?;
    let swap_chain = swap_chain.ok_or_else(|| {
        let error = windows::core::Error::new(
            windows::core::Error::from_win32().into(),
            "SwapChain is None",
        );
        write_log("SwapChain is None");
        error
    })?;

    let back_buffer: ID3D11Texture2D = unsafe {
        swap_chain
            .GetBuffer(0)
            .map_err(|e| {
                write_log(&format!("GetBuffer failed: {:?}", e));
                windows::core::Error::new(e.code(), "Failed to get back buffer")
            })?
    };

    let mut render_target_view: Option<ID3D11RenderTargetView> = None;
    unsafe {
        device
            .CreateRenderTargetView(&back_buffer, None, Some(&mut render_target_view))
            .map_err(|e| {
                write_log(&format!("CreateRenderTargetView failed: {:?}", e));
                windows::core::Error::new(e.code(), "Failed to create RTV")
            })?;
    }
    let rtv = render_target_view.ok_or_else(|| {
        let error = windows::core::Error::new(
            windows::core::Error::from_win32().into(),
            "RTV is None",
        );
        write_log("RenderTargetView is None");
        error
    })?;

    unsafe {
        context.OMSetRenderTargets(Some(&[Some(rtv.clone())]), None);
    }

    write_log("D3D render target view set successfully");
    Ok(D3DResources {
        device,
        context,
        swap_chain,
        render_target_view: rtv,
    })
}

/// Makes a virtual table entry writable to allow function pointer modification.
///
/// This function changes the memory protection of a specific memory region
/// to allow writing, which is necessary for function hooking.
///
/// # Safety
///
/// Modifies memory protection, which can cause system instability if used incorrectly.
///
/// # Arguments
///
/// * `ptr` - Pointer to the memory region to be made writable
///
/// # Returns
///
/// A `WinResult` indicating successful memory protection modification
///
/// # Errors
///
/// Returns an error if virtual memory protection change fails
unsafe fn make_vtable_writable(ptr: *mut core::ffi::c_void) -> WinResult<()> {
    write_log("make_vtable_writable called");
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    match VirtualProtect(
        ptr,
        size_of::<usize>(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    ) {
        Ok(_) => {
            write_log("VirtualProtect succeeded");
            Ok(())
        },
        Err(e) => {
            write_log(&format!("VirtualProtect failed: {:?}", e));
            Err(windows::core::Error::from_win32())
        }
    }
}

/// Hooks the `Present` method of the IDXGISwapChain to intercept rendering calls.
///
/// Performs the following steps:
/// - Creates a dummy window and Direct3D resources
/// - Locates the `Present` function in the swap chain's virtual table
/// - Stores the original `Present` function pointer
/// - Replaces the original function pointer with the custom `hooked_present`
///
/// # Safety
///
/// Modifies function pointers directly, which requires careful memory management
///
/// # Returns
///
/// A `WinResult` indicating successful swap chain hooking
///
/// # Errors
///
/// Returns an error if any step in the hooking process fails
unsafe fn hook_swapchain_present() -> WinResult<()> {
    let hinstance = GetModuleHandleW(PCWSTR::null())?;
    register_window_class(hinstance.into())?;
    let dummy_hwnd = create_overlay_window(hinstance.into())?;

    let (_dummy_device, _dummy_context, dummy_swap_chain, _dummy_rtv) = {
        let d3d = initialize_d3d(dummy_hwnd)?;
        (
            d3d.device,
            d3d.context,
            d3d.swap_chain,
            d3d.render_target_view,
        )
    };

    let swap_chain_vtable_ptr =
        *(dummy_swap_chain.as_raw() as *const *const *const core::ffi::c_void);

    let present_fn_ptr = swap_chain_vtable_ptr.add(8);

    ORIGINAL_PRESENT_PTR.get_or_init(|| SyncPtr(*present_fn_ptr));

    make_vtable_writable(present_fn_ptr as *mut core::ffi::c_void)?;
    *(present_fn_ptr as *mut *const core::ffi::c_void) = hooked_present as *const core::ffi::c_void;

    Ok(())
}

/// Renders the overlay for each frame.
///
/// Performs the following rendering tasks:
/// - Clears the render target view with a semi-transparent red color
/// - Presents the rendered frame to the swap chain
///
/// # Remarks
///
/// - Uses the Direct3D resources from the overlay manager
/// - Logs any rendering or presentation errors
///
/// # Panics
///
/// May panic if Direct3D resources are not properly initialized
fn render_overlay() {
    write_log("render_overlay called");

    if let Some(overlay_manager) = OVERLAY_MANAGER.get() {
        let manager = overlay_manager.lock().unwrap();
        if let Some(ref resources) = manager.d3d_resources {
            let context = &resources.context;
            let swap_chain = &resources.swap_chain;
            let render_target_view = &resources.render_target_view;

            let clear_color = [1.0, 0.0, 0.0, 0.5];
            unsafe {
                context.ClearRenderTargetView(render_target_view, &clear_color);
                let present_result = swap_chain.Present(1, DXGI_PRESENT(0));
                if present_result.is_err() {
                    write_log(&format!("Present failed: {:?}", present_result));
                } else {
                    write_log("Present called successfully");
                }
            }
        } else {
            write_log("D3D resources are not initialized");
        }
    } else {
        write_log("Overlay manager is not initialized");
    }
}

#[no_mangle]
pub extern "stdcall" fn DllMain(_: *mut u8, reason: u32, _: *mut u8) -> bool {
    write_log(&format!("DllMain called with reason: {}", reason));

    if reason == 1 {
        std::thread::spawn(|| {
            unsafe {
                if let Err(e) = hook_swapchain_present() {
                    write_log(&format!("Failed to hook swapchain: {:?}", e));
                } else {
                    write_log("Swapchain hooked successfully");
                }
            }
        });
    }
    true
}
