


use std::os::unix::process::CommandExt as _;

use anyhow::Result;
use nix::{libc::ENOSYS, sys::{ptrace, signal::Signal, wait::wait}};



fn main() {
    println!("[INFO] Server PID: {}", std::process::id());

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Child) => run_as_client(),
        Ok(nix::unistd::ForkResult::Parent { child }) => run_as_server(child),
        Err(e) => panic!("Couldn't fork the main process: {}", e),
    };
}

fn run_as_client() {
    println!("[INFO] Client PID: {}", std::process::id());

    // `Command::exec` doesn't change the PID, so we can just ask now.
    ptrace::traceme().expect("OS could not be bothered to trace me");
    let e = std::process::Command::new("./target/debug/client").exec();

    unreachable!("Command::exec failed, this process should be dead: {e}")
}

fn run_as_server(pid: nix::unistd::Pid) {
    let ws = wait().expect("server failed to wait for client to be ready");
    println!("[INFO] Client ready with signal: {ws:?}");

    setup_tracing(pid).unwrap();
    ptrace::syscall(pid, None).unwrap();

    loop {
        match wait_for_signal() {
            Ok(_) => {}
            Err(e) => {
                println!("Error: {e}");
                break;
            }
        }
    }
}

fn wait_for_signal() -> Result<()> {
    match wait()? {
        nix::sys::wait::WaitStatus::Stopped(pid_t, sig_num) => {
            handle_client_stopped(sig_num, pid_t)
        }

        nix::sys::wait::WaitStatus::Exited(pid, exit_status) => {
            println!("Child with pid: {} exited with status {}", pid, exit_status);
            Ok(())
        }

        nix::sys::wait::WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, _) => {
            println!("PtraceEvent.SIGTRAP for: {pid} ");
            setup_tracing(pid)?;
            ptrace::syscall(pid, Some(Signal::SIGTRAP))?;
            Ok(())
        }

        status => {
            println!("Received unhandled wait status: {:?}", status);
            Ok(())
        }
    }
}

fn handle_client_stopped(sig_num: Signal, pid_t: nix::unistd::Pid) -> Result<()> {
    match sig_num {
        Signal::SIGTRAP => {
            handle_sigtrap(pid_t)?;
            Ok(ptrace::syscall(pid_t, None)?)
        }
        Signal::SIGSTOP => {
            println!("SIGSTOP in {pid_t}");
            Ok(ptrace::syscall(pid_t, Some(Signal::SIGSTOP))?)
        }
        Signal::SIGSEGV => Ok(ptrace::syscall(pid_t, Some(Signal::SIGSEGV))?),
        Signal::SIGWINCH => {
            println!("Received SIGWINCH");
            Ok(ptrace::syscall(pid_t, Some(Signal::SIGWINCH))?)
        }
        _ => {
            println!("Stopped with unexpected signal: {sig_num:?}");
            Ok(ptrace::syscall(pid_t, Some(sig_num))?)
        }
    }
}

fn handle_sigtrap(pid_t: nix::unistd::Pid) -> Result<()> {
    let regs = ptrace::getregs(pid_t)?;
    if regs.rax == -ENOSYS as u64 {
        // Syscall started. We're not blocking anything (yet), so do nothing.
        return Ok(());
    }

    // println!("SC @ {pid_t} :");
    print_syscall(&regs);

    Ok(())
}

fn setup_tracing(pid: nix::unistd::Pid) -> Result<()> {
    ptrace::setoptions(
        pid,
        ptrace::Options::PTRACE_O_TRACEFORK
            .union(ptrace::Options::PTRACE_O_TRACECLONE)
            .union(ptrace::Options::PTRACE_O_TRACEVFORK),
    )?;

    Ok(())
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

        257 => println!("openat(dfd={}, filename={}, flags={}, mode={})",
            regs.rdi, regs.rsi, regs.rdx, regs.r10),
        262 => println!("newfstatat(dfd={}, filename={}, statbuf={}, flags={})",
            regs.rdi, regs.rsi, regs.rdx, regs.r10),

        317 => println!("seccomp(op={}, flags={}, uargs={})", regs.rdi, regs.rsi, regs.rdx),
        318 => println!("getrandom(buf={}, count={}, flags={})", regs.rdi, regs.rsi, regs.rdx),

        other => println!("Unknown Syscall: {other}"),
    }
}
