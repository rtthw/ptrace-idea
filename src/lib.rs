


use anyhow::Result;
use nix::{libc::{ptrace_syscall_info, EPERM, PTRACE_EVENT_SECCOMP}, sys::{ptrace, signal::Signal, wait::{wait, WaitStatus}}, unistd::Pid};



/// This function assumes that there is only one running child of this process.
pub fn wait_for_event() -> Result<WaitEvent> {
    let status = wait()?;
    match status {
        WaitStatus::Exited(pid, code) => {
            Ok(WaitEvent::Exit { pid, code })
        }
        WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, event) => match event {
            PTRACE_EVENT_SECCOMP => {
                let info = ptrace::syscall_info(pid)?;
                Ok(WaitEvent::Trace(TracedSyscall { pid, info }))
            }
            event => {
                anyhow::bail!("[\x1b[31mFATAL\x1b[0m] Received unhandled ptrace event: {:?}", event)
            }
        }
        status => {
            anyhow::bail!("[\x1b[31mFATAL\x1b[0m] Received unhandled wait status: {:?}", status)
        }
    }
}

pub enum WaitEvent {
    Exit {
        pid: Pid,
        code: i32,
    },
    Trace(TracedSyscall),
}



pub struct TracedSyscall {
    pub pid: Pid,
    pub info: ptrace_syscall_info,
}

impl TracedSyscall {
    pub fn deny(self) -> Result<()> {
        let mut regs = ptrace::getregs(self.pid)?;
        regs.orig_rax = { -1_i32 } as u64;
        regs.rax = { -EPERM } as u64;
        ptrace::setregs(self.pid, regs)?;

        Ok(())
    }
}
