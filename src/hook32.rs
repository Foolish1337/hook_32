use crate::utils::mem::{alloc, free, read_bytes, write_bytes};

pub struct Cfg<const LEN: usize> {
    pub is_hooked: bool,
    pub cave_addr: usize,       
    pub org_addr: usize,        //
    pub org_bytes: [u8; LEN],   //
    pub mod_bytes: Vec<u8>,     //
}

impl<const LEN: usize> Cfg<LEN> {
    pub const fn new(org_addr: usize, org_bytes: [u8; LEN]) -> Self {
        Self {
            is_hooked: false,
            cave_addr: 0,
            org_addr,
            org_bytes,
            mod_bytes: Vec::new(),
        }
    }

    fn check_origin_bytes(&self, hproc: isize) -> bool {
        let mut bytes_found = [0u8; LEN];
        if !unsafe { read_bytes(hproc, self.org_addr, &mut bytes_found, true) } {
            return false;
        }
        for i in 0..LEN {
            if bytes_found[i] != self.org_bytes[i] {
                return false;
            }
        }
        true
    }

    fn write_mod_bytes_at_cave(&self, hproc: isize) -> bool {
        unsafe { write_bytes(hproc, self.cave_addr, &self.mod_bytes, true) }
    }

    fn write_return_jmp_at_cave(&self, hproc: isize) -> bool {
        let ret_addr =
            self.org_addr as isize - (self.cave_addr + 5 + self.mod_bytes.len() - LEN) as isize;

        let ret_addr_bytes = ret_addr.to_ne_bytes();
        if ret_addr_bytes.len() == 0 {
            return false;
        }

        let mut ret_jmp_bytes: [u8; 5] = [0xE9, 0x00, 0x00, 0x00, 0x00];
        for i in 0..4 { // 4 -> 0, 1, 2, 3
            ret_jmp_bytes[i + 1] = ret_addr_bytes[i];
        }

        unsafe {
            write_bytes(
                hproc,
                self.cave_addr + self.mod_bytes.len(),
                &ret_jmp_bytes,
                true,
            )
        }
    }

    // Write `jmp 0xFOOBAR` (0xFOOBAR = Origin Address) at the end,
    fn write_jmp_to_cave_at_origin(&self, hproc: isize) -> bool {
        let jmp_size: usize = 5;
        let jmp_addr = self.cave_addr as isize - (self.org_addr + 5) as isize;

        let jmp_addr_bytes = jmp_addr.to_ne_bytes(); // Native endian bytes of jmp address (lookup "endianness")
        if jmp_addr_bytes.len() == 0 {
            return false;
        }

        // Add first 5 jmp bytes
        let mut jmp_bytes = [0u8; LEN];
        jmp_bytes[0] = 0xE9;
        for i in 0..4 {
            jmp_bytes[i + 1] = jmp_addr_bytes[i];
        }

        // Nop extra bytes
        for i in jmp_size..LEN {
            jmp_bytes[i] = 0x90;
        }

        unsafe { write_bytes(hproc, self.org_addr, &jmp_bytes, true) }
    }

    pub fn set_hook(&mut self, hproc: isize) -> bool {
        if self.is_hooked || LEN < 5 || self.org_addr == 0 {
            return false;
        }
        if !self.check_origin_bytes(hproc) {
            return false;
        }
        // Allocate memory for mod bytes
        //println!("Allocating mem...");
        self.cave_addr = unsafe { alloc(hproc, 4096) };
        if self.cave_addr == 0 {
            return false;
        }

        // Write mod bytes at that memory
        //println!("Writing mod bytes...");
        if !self.write_mod_bytes_at_cave(hproc) {
            unsafe { free(hproc, self.cave_addr) };
            return false;
        }
        // Write at cave's end: jmp 0x(relative_origin_addr)
        //println!("Writing jmp return...");
        if !self.write_return_jmp_at_cave(hproc) {
            unsafe { free(hproc, self.cave_addr) };
            return false;
        }
        // Write at origin: jmp 0x(mod_code_addr)
        //println!("Writing jmp cave...");
        if !self.write_jmp_to_cave_at_origin(hproc) {
            return false;
        }

        self.is_hooked = true;
        true
    }

    pub fn unset_hook(&mut self, hproc: isize) -> bool {
        if !self.is_hooked {
            return false;
        }
        unsafe {
            if !write_bytes(hproc, self.org_addr, &self.org_bytes, true) {
                return false;
            }
            if !free(hproc, self.cave_addr) {
                return false;
            }
        }

        self.is_hooked = false;
        true
    }

    pub fn toggle_hook(&mut self, hproc: isize) -> bool {
        if self.is_hooked {
            return self.unset_hook(hproc);
        }
        self.set_hook(hproc)
    }
}
