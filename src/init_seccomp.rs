//! Seccomp initialization



use anyhow::Result;
use nix::libc;



pub const DEFAULT_RULES: &[FilterRule] = &[
    FilterRule::LoadSyscall,

    FilterRule::IfSyscallIs(sys::SYS_CUSTOM as u32),
    FilterRule::TraceSyscall,

    FilterRule::IfSyscallIs(libc::SYS_read as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_write as u32),
    FilterRule::AllowSyscall,

    FilterRule::IfSyscallIs(libc::SYS_access as u32),
    FilterRule::TraceSyscall,
    FilterRule::IfSyscallIs(libc::SYS_fstat as u32),
    FilterRule::TraceSyscall,
    FilterRule::IfSyscallIs(libc::SYS_statx as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_newfstatat as u32),
    FilterRule::AllowSyscall,

    FilterRule::IfSyscallIs(libc::SYS_open as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_openat as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_close as u32),
    FilterRule::AllowSyscall,

    FilterRule::IfSyscallIs(libc::SYS_dup as u32),
    FilterRule::AllowSyscall,

    FilterRule::IfSyscallIs(libc::SYS_mmap as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_mprotect as u32),
    FilterRule::AllowSyscall,

    FilterRule::IfSyscallIs(libc::SYS_brk as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_exit as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_rseq as u32),
    FilterRule::AllowSyscall,

    FilterRule::IfSyscallIs(libc::SYS_prctl as u32),
    FilterRule::AllowSyscall,

    FilterRule::IfSyscallIs(libc::SYS_gettid as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_set_tid_address as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_set_robust_list as u32),
    FilterRule::AllowSyscall,

    FilterRule::IfSyscallIs(libc::SYS_rt_sigaction as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_rt_sigreturn as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_rt_sigprocmask as u32),
    FilterRule::AllowSyscall,
    FilterRule::IfSyscallIs(libc::SYS_sigaltstack as u32),
    FilterRule::TraceSyscall,

    FilterRule::IfSyscallIs(libc::SYS_clone as u32),
    FilterRule::TraceSyscall,
    FilterRule::IfSyscallIs(libc::SYS_fork as u32),
    FilterRule::TraceSyscall,
    FilterRule::IfSyscallIs(libc::SYS_execve as u32),
    FilterRule::AllowSyscall,

    // FilterRule::IfSyscallIs(158), // arch_prctl
    // FilterRule::TraceSyscall,

    FilterRule::TraceSyscall,
];



pub struct Seccomp {
    bpf: Vec<libc::sock_filter>,
}

impl Seccomp {
    pub fn new(rules: &[FilterRule]) -> Self {
        let mut bpf = Vec::new();

        for rule in rules {
            rule.add_to_bpf(&mut bpf);
        }

        Self {
            bpf,
        }
    }

    pub fn activate(&mut self) -> Result<()> {
        // Ensure the `no_new_privs` bit is set.
        unsafe {
            let result = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if result != 0 {
                anyhow::bail!(result as usize)
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
            0,
            &program as *const libc::sock_fprog as usize,
        );

        // Return.
        if result == 0 {
            Ok(())
        } else {
            anyhow::bail!(result)
        }
    }
}

pub enum FilterRule {
    LoadSyscall,
    IfSyscallIs(u32),
    AllowSyscall,
    TraceSyscall,
    KillProcess,
}

impl FilterRule {
    fn add_to_bpf(&self, bpf: &mut Vec<libc::sock_filter>) {
        match self {
            FilterRule::LoadSyscall => {
                bpf.push(libc::sock_filter {
                    code: (libc::BPF_LD + libc::BPF_W + libc::BPF_ABS) as u16,
                    k: 0,
                    jt: 0,
                    jf: 0,
                });
            }
            FilterRule::IfSyscallIs(n) => {
                bpf.push(libc::sock_filter {
                    code: (libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K) as u16,
                    k: *n,
                    jt: 0,
                    jf: 1,
                });
            }
            FilterRule::AllowSyscall => {
                bpf.push(libc::sock_filter {
                    code: (libc::BPF_RET + libc::BPF_K) as u16,
                    k: libc::SECCOMP_RET_ALLOW,
                    jt: 0,
                    jf: 0,
                });
            }
            FilterRule::TraceSyscall => {
                bpf.push(libc::sock_filter {
                    code: (libc::BPF_RET + libc::BPF_K) as u16,
                    k: libc::SECCOMP_RET_TRACE,
                    jt: 0,
                    jf: 0,
                });
            }
            FilterRule::KillProcess => {
                bpf.push(libc::sock_filter {
                    code: (libc::BPF_RET + libc::BPF_K) as u16,
                    k: libc::SECCOMP_RET_KILL,
                    jt: 0,
                    jf: 0,
                });
            }
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
