#![no_std]
#![no_main]

extern crate alloc;
pub mod pelib;
pub mod test;
pub mod utils;
pub mod windows;

use pelib::{
    fix_base_relocations, get_dos_header, get_headers_size, get_image_size, get_nt_header,
    write_import_table, write_sections,
};
use utils::detect_platform;
use windows::{VirtualAlloc, MEM_COMMIT, PAGE_EXECUTE_READWRITE};

use core::ffi::c_void;

#[cfg(target_arch = "x86_64")]
type ImageNtHeaders = windows::IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
type ImageNtHeaders = windows::IMAGE_NT_HEADERS32;

pub enum RspeError {
    PlatformNotFound,
    DifferentPlatform, // The platform is not the same as the imported pe.
}

/// Compares the platform of the imported Portable Executable (PE) file with the platform of the compiled binary.
/// Panic if not same platforms
///
/// # Arguments
///
/// * `data` - A vector containing the bytes of the PE file to be loaded.
fn is_platforms_same(data: &[u8]) -> Result<(), RspeError> {
    let Some(platform) = detect_platform(data) else {
        return Err(RspeError::PlatformNotFound);
    };

    let target_arch = if cfg!(target_arch = "x86_64") { 64 } else { 32 };

    if platform != target_arch {
        Err(RspeError::DifferentPlatform)
    } else {
        Ok(())
    }
}

/// Loads a Portable Executable (PE) file into memory using reflective loading.
///
/// # Arguments
///
/// * `buffer` - A vector containing the bytes of the PE file to be loaded.
///
/// # Safety
///
/// This function is unsafe because it directly interacts with the Windows API and modifies memory
/// in the target process.
pub unsafe fn reflective_loader(buffer: &[u8]) -> Result<(), RspeError> {
    is_platforms_same(buffer)?;

    // Get the size of the headers and the image
    let headerssize = get_headers_size(buffer);
    let imagesize = get_image_size(buffer);
    let buf_ptr = buffer.as_ptr() as *const c_void;

    // Allocate memory for the image
    let baseptr = VirtualAlloc(
        core::ptr::null_mut(), // lpAddress: A pointer to the starting address of the region to allocate.
        imagesize,             // dwSize: The size of the region, in bytes.
        MEM_COMMIT,            // flAllocationType: The type of memory allocation.
        PAGE_EXECUTE_READWRITE, // flProtect: The memory protection for the region of pages to be allocated.
    );

    // Write the headers to the allocated memory
    core::ptr::copy_nonoverlapping(buf_ptr, baseptr, headerssize);

    // Get the DOS header
    let dosheader = get_dos_header(buf_ptr);

    // Get the NT header IMAGE_NT_HEADERS64|IMAGE_NT_HEADERS32
    let ntheader = get_nt_header(buf_ptr, dosheader);

    // Write each section to the allocated memory
    write_sections(
        baseptr,   // The base address of the image.
        &buffer,   // The buffer containing the image.
        ntheader,  // The NT header of the image.
        dosheader, // The DOS header of the image.
    );

    // Write the import table to the allocated memory
    write_import_table(baseptr, ntheader);

    // Fix the base relocations
    fix_base_relocations(baseptr, ntheader);

    let entrypoint = (baseptr as usize
        + (*(ntheader as *const ImageNtHeaders))
            .OptionalHeader
            .AddressOfEntryPoint as usize) as *const c_void;

    // Create a new thread to execute the image
    execute_image(entrypoint);

    // Free the allocated memory of baseptr
    let _ = baseptr;
    
    Ok(())
}

/// Executes the image by calling its entry point and waiting for the thread to finish executing.
///
/// # Arguments
///
/// * `entrypoint` - A pointer to the PE file entrypoint.
///
/// # Safety
///
/// This function is unsafe because it directly interacts with the Windows API and modifies memory
/// in the target process.
unsafe fn execute_image(entrypoint: *const c_void) {
    // Call the entry point of the image
    let func: extern "C" fn() -> u32 = core::mem::transmute(entrypoint);
    func();
}
