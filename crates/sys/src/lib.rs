


#![no_std]



#[inline]
pub fn syscall1(
    n: usize,
    arg1: usize,
) -> usize {
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
pub fn syscall2(
    n: usize,
    arg1: usize,
    arg2: usize,
) -> usize {
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
