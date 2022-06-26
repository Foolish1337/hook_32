use super::utils::{mem, proc};
use super::hook32;

type FARPROC = Option<unsafe extern "system" fn() -> isize>;

extern "system" {
    fn GetProcAddress(hmodule: isize, lpprocname: *const u8) -> FARPROC;
    fn LoadLibraryW(lplibfilename: *const u16) -> isize;
    fn GetLastError() -> u32;
}

fn to_wstr(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn error(msg: &str) -> String {
	format!("{} [LastError: {}]", msg, unsafe { GetLastError() })
}

static mut HOOK_CFG: hook32::Cfg<5> = hook32::Cfg::new(0, [0u8; 5]);

pub unsafe fn set() -> Result<(), String> {
	let target_proc = proc::get_processes_by_name("notepad.exe", proc::AccessRights::ReadWriteOperate).unwrap()[0].to_owned();

    let hlib = LoadLibraryW(to_wstr("C:/Windows/System32/USER32.dll").as_ptr());
    if hlib <= 0 { return Err(error("'LoadLibraryW' failed")) }

    let fn_name = "MessageBoxW\0";
    let fn_addr = match GetProcAddress(hlib, fn_name.as_ptr()) {
    	Some(addr) => addr as usize,
    	None => return Err(error("'GetProcAddress' failed")),
    };
    println!("MessageBoxW Addr: {:X}", fn_addr as usize);

    let mut original_fn_bytes = [0u8; 5];
    if !mem::read_bytes(target_proc.handle, fn_addr, &mut original_fn_bytes, true) {
    	return Err(error("'read_bytes' failed"))
    }

    HOOK_CFG.org_addr = fn_addr;
    HOOK_CFG.org_bytes = original_fn_bytes; 

    HOOK_CFG.mod_bytes = vec![0x90]; 
    if !HOOK_CFG.set_hook(target_proc.handle) {
    	return Err(error("'set_hook' failed"));
    }

    Ok(())
}