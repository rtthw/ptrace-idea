//! Seccomp initialization



use nix::libc;



pub struct Seccomp {
    bpf: Vec<libc::sock_filter>,
}

impl Seccomp {
    pub fn new() -> Self {
        Self {
            bpf: Vec::new(),
        }
    }

    pub fn activate(&mut self) -> Result<(), usize> {
        // Ensure the `no_new_privs` bit is set.
        unsafe {
            let result = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if result != 0 {
                return Err(result as usize)
            }
        }

        // Activate `seccomp`.
        let program = libc::sock_fprog {
            len: self.bpf.len() as libc::c_ushort,
            filter: self.bpf.as_mut_ptr(),
        };
        let result = syscall3(
            libc::SYS_seccomp as _,
            libc::SECCOMP_SET_MODE_FILTER as usize,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as usize,
            &program as *const libc::sock_fprog as usize,
        );

        // Return.
        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }
}



#[inline]
pub fn syscall3(
    n: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> usize {
    let mut ret: usize;
    unsafe { core::arch::asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        out("rcx") _, // rcx is used to store old rip
        out("r11") _, // r11 is used to store old rflags
        options(nostack, preserves_flags)
    ) };
    ret
}
