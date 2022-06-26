// I wrote this when i had just started with rust
// It's good enough for our (and most) use case

#[allow(non_snake_case, dead_code)]
#[derive(Copy, Clone)]
pub enum AccessRights {
    VmOperation = 0x8,
    VmRead = 0x10,
    VmWrite = 0x20,
    StandardRightsRequired = 0x000F0000,
    AllAccess = 0xF0000 | 0x100000 | 0xFFFF,

    ReadWriteOperate = 0x10 | 0x20 | 0x8,
}

#[repr(C)]
#[allow(non_snake_case)]
struct ProcessEntry32 {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [u8; 260],
}

#[derive(Debug, Default, Clone)]
pub struct Process {
    pub id: u32,
    pub name: String,
    pub handle: isize,
}

extern "system" {
    fn CreateToolhelp32Snapshot(dwflags: u32, th32processid: u32) -> isize;
    fn Process32First(hsnapshot: isize, lppe: *mut ProcessEntry32) -> i32;
    fn Process32Next(hsnapshot: isize, lppe: *mut ProcessEntry32) -> i32;
    fn OpenProcess(dwdesiredaccess: u32, binherithandle: bool, dwprocessid: u32) -> isize;
    fn CloseHandle(hobject: isize) -> i32;
}

fn custom_bytes_to_string(buffer: &[u8]) -> String {
    match String::from_utf8(buffer.to_vec()) {
        Ok(mut name) => {
            // println!("nmae: {:?}", name);
            match name.find('\0') {
                Some(index) => name.truncate(index),
                None => (),
            }
            name
        }
        Err(err) => format!("?? -> {}", err),
    }
}

pub unsafe fn get_all_processes() -> Result<Vec<Process>, String> {
    let mut procs: Vec<Process> = Vec::new();
    let mut pe32 = core::mem::zeroed::<ProcessEntry32>();
    
    //0x2 = TH32CS_SNAPPROCESS
    let snapshot = CreateToolhelp32Snapshot(0x2, 0);
    if snapshot <= 0 {
        return Err("Invalid process snapshot".into());
    }

    pe32.dwSize = std::mem::size_of::<ProcessEntry32>() as u32;

    if Process32First(snapshot, &mut pe32) <= 0 {
        CloseHandle(snapshot);
        return Err("Failed to get first process info from snapshot".into());
    }

    loop {
        if pe32.th32ProcessID != 0 {
            procs.push(Process {
                id: pe32.th32ProcessID,
                name: custom_bytes_to_string(&pe32.szExeFile),
                handle: 0,
            });
        }

        if Process32Next(snapshot, &mut pe32) <= 0 {
            break;
        }
    }

    CloseHandle(snapshot);

    if procs.len() == 0 {
        return Err("Failed to get a list of all running processes".to_string());
    }

    Ok(procs)
}

pub fn get_processes_by_name(
    name: &str,
    access_rights: AccessRights,
) -> Result<Vec<Process>, String> {

    let procs = unsafe { get_all_processes()? };
    let mut found_procs: Vec<Process> = Vec::new();

    for mut proc in procs.into_iter() {
        if proc.name != name {
            continue;
        }

        proc.handle = unsafe { OpenProcess(access_rights as u32, false, proc.id) };
        if proc.handle <= 0 {
            return Err("Got invalid process handle".into());
        }

        found_procs.push(proc.to_owned());
    }

    if found_procs.len() == 0 {
        return Err(format!("No process found by the name: {}", name));
    }

    Ok(found_procs)
}