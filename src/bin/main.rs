/*!
# DLL Injector

This Rust program facilitates the injection of a Dynamic Link Library (DLL) into a target Windows process. Specifically designed to inject `dx11_hook.dll` into the `ffxiv_dx11.exe` process, it leverages Windows API functions to manipulate the target process's memory space and execute remote threads. This technique is commonly used for extending application functionalities, debugging, or, in some cases, for malicious purposes.

## Key Features

- **Process Identification**:
  - Utilizes the `sysinfo` crate to enumerate running processes and identify the target process (`ffxiv_dx11.exe`).

- **Process Access and Memory Management**:
  - Opens the target process with `PROCESS_ALL_ACCESS` permissions using `OpenProcess`.
  - Allocates memory within the target process's address space using `VirtualAllocEx` with `MEM_COMMIT` and `MEM_RESERVE` flags.
  - Writes the DLL path into the allocated memory using `WriteProcessMemory`.

- **DLL Injection Mechanism**:
  - Retrieves the address of the `LoadLibraryA` function from `kernel32.dll` using `GetModuleHandleA` and `GetProcAddress`.
  - Creates a remote thread in the target process that invokes `LoadLibraryA`, effectively loading the specified DLL into the process.

- **Error Handling and Logging**:
  - Implements robust error handling to capture and report failures at each stage of the injection process.
  - Provides user feedback through console messages, indicating the success or failure of the injection steps.

- **User Interaction**:
  - Waits for user input before exiting, allowing users to read error messages or confirmations.

## Structure Overview

- **Imports**:
  - **Windows API Modules**:
    - `windows::Win32::System::Threading`, `Memory`, `Foundation`, `Diagnostics::Debug`, `LibraryLoader`: For process and memory management.
  - **Standard Libraries**:
    - `std::ffi::CString`, `std::ptr::null_mut`, `std::io::{self, Write}`: For string handling and I/O operations.
  - **Third-Party Crates**:
    - `sysinfo`: For retrieving system and process information.

- **Main Components**:
  - **`main` Function**:
    - Serves as the entry point, invoking the `run` function and handling any resulting errors.
    - Waits for user input before terminating to ensure that console messages remain visible.

  - **`run` Function**:
    - Coordinates the DLL injection process by performing the following steps:
      1. Defines the target process name and the DLL path.
      2. Locates the target process ID using `find_process_id`.
      3. Opens the target process with the necessary access rights.
      4. Allocates memory within the target process for the DLL path.
      5. Writes the DLL path into the allocated memory.
      6. Retrieves the address of `LoadLibraryA` from `kernel32.dll`.
      7. Creates a remote thread in the target process to execute `LoadLibraryA`, thereby loading the DLL.

  - **Helper Functions**:
    - **`find_process_id`**:
      - Searches for the target process by name and returns its Process ID (PID).
    - **`open_process`**:
      - Opens the target process with `PROCESS_ALL_ACCESS` rights.
    - **`allocate_remote_memory`**:
      - Allocates memory in the target process's address space for storing the DLL path.
    - **`write_dll_path_to_memory`**:
      - Writes the DLL path string into the allocated memory within the target process.
    - **`get_load_library_address`**:
      - Retrieves the memory address of the `LoadLibraryA` function from `kernel32.dll`.
    - **`inject_dll`**:
      - Creates a remote thread in the target process that calls `LoadLibraryA`, effectively injecting the DLL.

## Usage

To use this DLL injector:

1. **Preparation**:
   - Ensure that the target process (`ffxiv_dx11.exe` in our case) is running. 
   - Place the `dx11_hook.dll` in the same directory as the injector executable or update the `dll_path` accordingly.

2. **Execution**:
   - Compile the Rust program using Cargo or your preferred Rust compiler.
   - Run the resulting executable with appropriate permissions (administrator rights may be required).

3. **Injection Process**:
   - The program will search for the target process.
   - Upon locating the process, it will allocate memory, write the DLL path, and create a remote thread to load the DLL.
   - Success and error messages will be displayed in the console.

4. **Termination**:
   - After attempting the injection, the program waits for the user to press Enter before exiting, allowing time to review console messages.

**Note**: The target process name (`ffxiv_dx11.exe`) is currently hardcoded. To inject into a different process, modify the `target` variable accordingly. Additionally, ensure that injecting DLLs complies with software licenses and legal regulations.

*/

use windows::Win32::System::Threading::{PROCESS_ALL_ACCESS, OpenProcess, CreateRemoteThread};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use std::ffi::CString;
use std::ptr::null_mut;
use windows::core::PCSTR;
use std::io::{self, Write};

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
    }

    println!("Press Enter to exit...");
    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut String::new());
}

/// Injects a dll into the target process.
///
/// This function performs the following steps:
/// - Identifies the target process by name
/// - Determines the path to the DLL to be injected
/// - Opens a handle to the target process
/// - Allocates remote memory in the target process
/// - Writes the DLL path to the allocated memory
/// - Retrieves the address of LoadLibraryA
/// - Injects the DLL using CreateRemoteThread
///
/// # Returns
///
/// A `Result` indicating successful DLL injection or an error
///
/// # Errors
///
/// Returns an error if:
/// - Process cannot be found
/// - Memory allocation fails
/// - DLL path writing fails
/// - DLL injection fails
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let target = "ffxiv_dx11.exe"; // fix to not be hardcoded later
    let dll_path = std::env::current_dir()
        .unwrap()
        .join("dx11_hook.dll")
        .to_str()
        .unwrap()
        .to_string();
    
    let process_id = find_process_id(target).expect("Could not find process");
    let dll_path_c = CString::new(dll_path)?;
    let alloc_size = dll_path_c.as_bytes_with_nul().len();

    let process_handle = unsafe { open_process(process_id)? };
    let remote_mem = unsafe { allocate_remote_memory(process_handle, alloc_size)? };
    
    unsafe {
        write_dll_path_to_memory(process_handle, remote_mem, &dll_path_c, alloc_size)?;
        let (_kernel32, load_library_addr) = get_load_library_address()?;
        inject_dll(process_handle, remote_mem, load_library_addr)?;
    }
    
    Ok(())
}

/// Opens a handle to a process with full access rights.
///
/// # Arguments
///
/// * `process_id` - The process identifier to open
///
/// # Returns
///
/// A `Result` containing a handle to the process or an error
///
/// # Safety
///
/// This function is unsafe as it directly interacts with system process handles
unsafe fn open_process(process_id: u32) -> windows::core::Result<HANDLE> {
    OpenProcess(PROCESS_ALL_ACCESS, false, process_id)
}

/// Allocates memory in a remote process's address space.
///
/// # Arguments
///
/// * `process_handle` - Handle to the target process
/// * `size` - Size of memory to allocate
///
/// # Returns
///
/// A `Result` containing a pointer to the allocated memory or an error
///
/// # Safety
///
/// This function is unsafe as it directly allocates memory in another process
/// and requires proper memory management
///
/// # Errors
///
/// Returns an error if memory allocation fails, closing the process handle
unsafe fn allocate_remote_memory(process_handle: HANDLE, size: usize) -> windows::core::Result<*mut std::ffi::c_void> {
    let remote_mem = VirtualAllocEx(
        process_handle,
        Some(null_mut()),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if remote_mem.is_null() {
        CloseHandle(process_handle)?;
        return Err(windows::core::Error::from_win32());
    }
    Ok(remote_mem)
}

/// Writes the DLL path to memory in the target process.
///
/// # Arguments
///
/// * `process_handle` - Handle to the target process
/// * `remote_mem` - Pointer to the allocated remote memory
/// * `dll_path_c` - CString containing the DLL path
/// * `size` - Size of the DLL path to write
///
/// # Returns
///
/// A `Result` indicating successful memory writing or an error
///
/// # Safety
///
/// Unsafe function that writes memory in another process's address space
unsafe fn write_dll_path_to_memory(
    process_handle: HANDLE,
    remote_mem: *mut std::ffi::c_void,
    dll_path_c: &CString,
    size: usize,
) -> windows::core::Result<()> {
    WriteProcessMemory(
        process_handle,
        remote_mem,
        dll_path_c.as_ptr() as *const _,
        size,
        None,
    )
}

/// Retrieves the address of the LoadLibraryA function.
///
/// # Returns
///
/// A `Result` containing:
/// - Handle to kernel32.dll
/// - Address of the LoadLibraryA function
///
/// # Safety
///
/// Unsafe function that interacts with module and function addresses
///
/// # Errors
///
/// Returns an error if getting module handle or function address fails
unsafe fn get_load_library_address() -> windows::core::Result<(
    windows::Win32::Foundation::HMODULE, 
    Option<unsafe extern "system" fn() -> isize>
)> {
    let kernel32_str = "kernel32.dll\0";
    let kernel32 = GetModuleHandleA(PCSTR::from_raw(kernel32_str.as_ptr()))?;
    
    let load_library = "LoadLibraryA\0";
    let load_library_addr = GetProcAddress(kernel32, PCSTR::from_raw(load_library.as_ptr()));
    
    Ok((kernel32, load_library_addr))
}


/// Retrieves the address of the LoadLibraryA function.
///
/// # Returns
///
/// A `Result` containing:
/// - Handle to kernel32.dll
/// - Address of the LoadLibraryA function
///
/// # Safety
///
/// Unsafe function that interacts with module and function addresses
///
/// # Errors
///
/// Returns an error if getting module handle or function address fails
unsafe fn inject_dll(
    process_handle: HANDLE,
    remote_mem: *mut std::ffi::c_void,
    load_library_addr: Option<unsafe extern "system" fn() -> isize>,
) -> windows::core::Result<()> {
    if let Some(addr) = load_library_addr {
        let load_library_fn: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 = 
            std::mem::transmute(addr);

        let thread_handle = CreateRemoteThread(
            process_handle,
            Some(null_mut()),
            0,
            Some(load_library_fn),
            Some(remote_mem),
            0,
            Some(null_mut()),
        )?;

        if thread_handle.is_invalid() {
            CloseHandle(process_handle)?;
            return Err(windows::core::Error::from_win32());
        }

        println!("DLL injected successfully");
        CloseHandle(thread_handle)?;
        CloseHandle(process_handle)?;
    } else {
        CloseHandle(process_handle)?;
        return Err(windows::core::Error::from_win32());
    }

    Ok(())
}


/// Injects the DLL into the target process by creating a remote thread.
///
/// # Arguments
///
/// * `process_handle` - Handle to the target process
/// * `remote_mem` - Pointer to the remote memory containing DLL path
/// * `load_library_addr` - Address of the LoadLibraryA function
///
/// # Returns
///
/// A `Result` indicating successful DLL injection or an error
///
/// # Safety
///
/// Unsafe function that creates a thread in another process
///
/// # Errors
///
/// Returns an error if:
/// - Creating remote thread fails
/// - Thread handle is invalid
/// - Closing process or thread handle fails
fn find_process_id(p_name: &str) -> Option<u32> {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    for (pid, process) in sys.processes() {
        if process.name().eq_ignore_ascii_case(p_name) {
            return Some(pid.as_u32());
        }
    }
    None
}
