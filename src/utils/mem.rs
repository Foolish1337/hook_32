use std::ffi::c_void;

#[rustfmt::skip]
extern "system" {
    fn ReadProcessMemory(hprocess: isize, lpbaseaddress: *const c_void, lpbuffer: *mut c_void, nsize: usize, lpnumberofbytesread: *mut usize) -> i32;
    fn WriteProcessMemory(hprocess: isize, lpbaseaddress: *const c_void, lpbuffer: *const c_void, nsize: usize, lpnumberofbyteswritten: *mut usize) -> i32;
    fn VirtualProtectEx(hprocess: isize, lpaddress: *const c_void, dwsize: usize, flnewprotect: u32, lpfloldprotect: *mut u32) -> i32;
    fn VirtualAllocEx(hprocess: isize, lpaddress: *const c_void, dwsize: usize, flallocationtype: u32, flprotect: u32) -> *mut c_void;
    fn VirtualFreeEx(hprocess: isize, lpaddress: *mut c_void, dwsize: usize, dwfreetype: u32) -> i32;
}

#[rustfmt::skip]
pub unsafe fn read_bytes(hproc: isize, address: usize, buffer: &mut [u8], is_protected: bool) -> bool {
    if is_protected {
        let old_protection = &mut 0u32;
        // 0x40 = PAGE_EXECUTE_READWRITE
        if VirtualProtectEx(hproc, address as *const c_void, buffer.len(), 0x40, old_protection) <= 0 {
            return false;
        }
        if ReadProcessMemory(hproc, address as *const c_void, buffer as *mut [u8] as *mut c_void, buffer.len(), std::ptr::null_mut()) <= 0 {
            return false;
        }
        if VirtualProtectEx(hproc, address as *const c_void, buffer.len(), *old_protection, old_protection) <= 0 {
            return false;
        }
        return true;
    }

    ReadProcessMemory(hproc, address as *const c_void, buffer as *mut [u8] as *mut c_void, buffer.len(), std::ptr::null_mut()) > 0
}

#[rustfmt::skip]
pub unsafe fn write_bytes(hproc: isize, address: usize, bytes: &[u8], is_protected: bool) -> bool {
     if is_protected {
        let old_protection = &mut 0u32;
        // 0x40 = PAGE_EXECUTE_READWRITE
        if VirtualProtectEx(hproc, address as *const c_void, bytes.len(), 0x40, old_protection) <= 0 {
            return false;
        }
        if WriteProcessMemory(hproc, address as *const c_void, bytes as *const [u8] as *const c_void, bytes.len(), std::ptr::null_mut()) <= 0 {
            return false;
        }
        if VirtualProtectEx(hproc, address as *const _, bytes.len(), *old_protection, old_protection) <= 0 {
            return false;
        }
        return true;
    }

    WriteProcessMemory(hproc, address as *const c_void, bytes as *const [u8] as *const c_void, bytes.len(), std::ptr::null_mut()) > 0
}

pub unsafe fn alloc(hproc: isize, size: usize) -> usize {
    // 0x1000 = MEM_COMMIT, 0x2000 = MEM_RESERVE, 0x40 = PAGE_EXECUTE_READWRITE
    VirtualAllocEx(hproc, 0 as *const c_void, size, 0x1000 | 0x2000, 0x40) as usize
}

pub unsafe fn free(hproc: isize, address: usize) -> bool {
    // 0x8000 = MEM_RELEASE
    VirtualFreeEx(hproc, address as *mut c_void, 0, 0x8000) > 0
}