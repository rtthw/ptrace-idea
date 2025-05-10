


mod init_seccomp;

use anyhow::Result;
use init_seccomp::*;
use nix::{libc::{ENOSYS, PTRACE_EVENT_SECCOMP}, sys::{ptrace, signal::Signal, wait::wait}, unistd::Pid};



fn main() -> Result<()> {
    println!("[\x1b[33mINFO\x1b[0m] Server PID: {}", get_pid());

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Child) => run_as_client(),
        Ok(nix::unistd::ForkResult::Parent { child }) => run_as_server(child),
        Err(e) => panic!("[\x1b[31mFATAL\x1b[0m] Couldn't fork the main process: {}", e),
    }
}

fn run_as_client() -> Result<()> {
    println!("[\x1b[33mINFO\x1b[0m] Client PID: {}", get_pid());

    ptrace::traceme()?;
    Seccomp::new(init_seccomp::DEFAULT_RULES).activate()?;
    nix::unistd::execve(c"./target/debug/client", &[c""], &[c""])?;

    unsafe { nix::libc::exit(0) }
}

fn run_as_server(pid: Pid) -> Result<()> {
    let ws = wait().expect("[\x1b[31mERROR\x1b[0m] Server failed to wait for client to be ready");
    println!("[\x1b[33mINFO\x1b[0m] Client {pid} ready with signal: {ws:?}");

    ptrace::setoptions(
        pid,
        ptrace::Options::PTRACE_O_TRACESECCOMP,
    )?;
    ptrace::syscall(pid, None)?;

    let mut rt = Runtime {};
    loop {
        match wait_for_signal(&mut rt) {
            Ok(_) => {}
            Err(e) => {
                println!("[\x1b[31mERROR\x1b[0m] {e}");
                break;
            }
        }
    }

    Ok(())
}

fn wait_for_signal(rt: &mut Runtime) -> Result<()> {
    match wait()? {
        nix::sys::wait::WaitStatus::Stopped(pid, sig) => {
            handle_client_stopped(rt, sig, pid)
        }
        nix::sys::wait::WaitStatus::Exited(pid, exit_status) => {
            println!("Child with pid: {} exited with status {}", pid, exit_status);
            Ok(())
        }
        nix::sys::wait::WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, PTRACE_EVENT_SECCOMP) => {
            println!("PTRACE_EVENT_SECCOMP @ {pid}");
            rt.handle_syscall(Syscall::get(pid)?)
        }
        nix::sys::wait::WaitStatus::PtraceSyscall(pid) => {
            println!("PTRACE_SYSCALL @ {pid}");
            ptrace::cont(pid, None)?;
            Ok(())
        }
        status => {
            anyhow::bail!("[FATAL] Received unhandled wait status: {:?}", status)
        }
    }
}

fn handle_client_stopped(rt: &mut Runtime, sig: Signal, pid: Pid) -> Result<()> {
    match sig {
        Signal::SIGTRAP => {
            rt.handle_syscall(Syscall::get(pid)?)
        }
        Signal::SIGSTOP => {
            println!("SIGSTOP in {pid}");
            Ok(ptrace::syscall(pid, Some(Signal::SIGSTOP))?)
        }
        Signal::SIGSEGV => Ok(ptrace::syscall(pid, Some(Signal::SIGSEGV))?),
        Signal::SIGWINCH => {
            println!("Received SIGWINCH");
            Ok(ptrace::syscall(pid, Some(Signal::SIGWINCH))?)
        }
        _ => {
            println!("Stopped with unexpected signal: {sig:?}");
            Ok(ptrace::syscall(pid, Some(sig))?)
        }
    }
}



fn print_syscall(regs: &nix::libc::user_regs_struct) {
    match regs.orig_rax {
        0 => println!("read(fd={}, buf={}, count={})", regs.rdi, regs.rsi, regs.rdx),
        1 => println!("write(fd={}, buf={}, count={})", regs.rdi, regs.rsi, regs.rdx),
        2 => println!("open(filename={}, flags={}, mode={})", regs.rdi, regs.rsi, regs.rdx),
        3 => println!("close(fd={})", regs.rdi),

        4 => println!("stat(filename={}, statbuf={})", regs.rdi, regs.rsi),
        5 => println!("fstat(fd={}, statbuf={})", regs.rdi, regs.rsi),
        6 => println!("lstat(filename={}, statbuf={})", regs.rdi, regs.rsi),

        7 => println!("poll(ufds={}, nfds={}, timeout_msecs={})", regs.rdi, regs.rsi, regs.rdx),
        8 => println!("lseek(fd={}, offset={}, origin={})", regs.rdi, regs.rsi, regs.rdx),

        9 => println!("mmap(addr={}, len={}, prot={}, flags={}, fd={}, off={})",
            regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9),
        10 => println!("mprotect(start={}, len={}, prot={})", regs.rdi, regs.rsi, regs.rdx),
        11 => println!("munmap(addr={}, len={})", regs.rdi, regs.rsi),

        12 => println!("brk(brk={})", regs.rdi),

        17 => println!("pread64(fd={}, buf={}, count={}, pos={})",
            regs.rdi, regs.rsi, regs.rdx, regs.r10),
        18 => println!("pwrite64(fd={}, buf={}, count={}, pos={})",
            regs.rdi, regs.rsi, regs.rdx, regs.r10),

        21 => println!("access(filename={}, mode={})", regs.rdi, regs.rsi),

        29 => println!("shmget(key={}, size={}, shmflg={})", regs.rdi, regs.rsi, regs.rdx),
        30 => println!("shmat(shmid={}, shmaddr={}, shmflg={})", regs.rdi, regs.rsi, regs.rdx),
        31 => println!("shmctl(shmid={}, cmd={}, buf={})", regs.rdi, regs.rsi, regs.rdx),

        158 => println!("arch_prctl(task={}, code={}, addr={})", regs.rdi, regs.rsi, regs.rdx),
        218 => println!("set_tid_address(tidptr={})", regs.rdi),
        219 => println!("restart_syscall()"),
        273 => println!("set_robust_list(head={}, len={})", regs.rdi, regs.rsi),
        274 => println!("get_robust_list(pid={}, head_ptr={}, len_ptr={})",
            regs.rdi, regs.rsi, regs.rdx),

        257 => println!("openat(dfd={}, filename={}, flags={}, mode={})",
            regs.rdi, regs.rsi, regs.rdx, regs.r10),
        262 => println!("newfstatat(dfd={}, filename={}, statbuf={}, flags={})",
            regs.rdi, regs.rsi, regs.rdx, regs.r10),

        317 => println!("seccomp(op={}, flags={}, uargs={})", regs.rdi, regs.rsi, regs.rdx),
        318 => println!("getrandom(buf={}, count={}, flags={})", regs.rdi, regs.rsi, regs.rdx),

        334 => println!("rseq()"),

        other => println!("Unknown Syscall: {other}"),
    }
}

fn get_pid() -> i32 {
    unsafe { nix::libc::getpid() }
}



pub struct Runtime {}

impl Runtime {
    pub fn handle_syscall(&mut self, syscall: Syscall) -> Result<()> {
        if syscall.is_entry() {
            syscall.allow(None)?;
        } else {
            syscall.print();
            syscall.allow(None)?;
        }

        Ok(())
    }
}



pub struct Syscall {
    pid: Pid,
    regs: nix::libc::user_regs_struct,
}

impl Syscall {
    pub fn get(pid: Pid) -> Result<Self> {
        Ok(Self {
            pid,
            regs: ptrace::getregs(pid)?,
        })
    }

    pub fn is_entry(&self) -> bool {
        self.regs.rax == -ENOSYS as u64
    }

    pub fn print(&self) {
        print!("[\x1b[33mINFO\x1b[0m @ {}] Syscall: ", self.pid);
        print_syscall(&self.regs);
    }

    pub fn allow(self, signal: impl Into<Option<Signal>>) -> Result<()> {
        ptrace::syscall(self.pid, signal)?;
        Ok(())
    }
}
