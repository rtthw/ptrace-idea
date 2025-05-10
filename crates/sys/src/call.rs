//! Syscalls



#[inline]
pub fn call0(n: usize) -> usize {
    let mut ret: usize;
    unsafe { core::arch::asm!(
        "syscall",
        inlateout("rax") n => ret,
        out("rcx") _, // rcx is used to store old rip
        out("r11") _, // r11 is used to store old rflags
        options(nostack, preserves_flags)
    ) };
    ret
}

#[inline]
pub fn call1(n: usize, arg1: usize) -> usize {
    let mut ret: usize;
    unsafe { core::arch::asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") arg1,
        out("rcx") _, // rcx is used to store old rip
        out("r11") _, // r11 is used to store old rflags
        options(nostack, preserves_flags)
    ) };
    ret
}

#[inline]
pub fn call2(n: usize, arg1: usize, arg2: usize) -> usize {
    let mut ret: usize;
    unsafe { core::arch::asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") arg1,
        in("rsi") arg2,
        out("rcx") _, // rcx is used to store old rip
        out("r11") _, // r11 is used to store old rflags
        options(nostack, preserves_flags)
    ) };
    ret
}

#[inline]
pub fn call3(n: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
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

#[inline]
pub fn call4(n: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> usize {
    let mut ret: usize;
    unsafe { core::arch::asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        out("rcx") _, // rcx is used to store old rip
        out("r11") _, // r11 is used to store old rflags
        options(nostack, preserves_flags)
    ) };
    ret
}

#[inline]
pub fn call5(n: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> usize {
    let mut ret: usize;
    unsafe { core::arch::asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        in("r8") arg5,
        out("rcx") _, // rcx is used to store old rip
        out("r11") _, // r11 is used to store old rflags
        options(nostack, preserves_flags)
    ) };
    ret
}

#[inline]
pub fn call6(
    n: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize
) -> usize {
    let mut ret: usize;
    unsafe { core::arch::asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        in("r8") arg5,
        in("r9") arg6,
        out("rcx") _, // rcx is used to store old rip
        out("r11") _, // r11 is used to store old rflags
        options(nostack, preserves_flags)
    ) };
    ret
}
