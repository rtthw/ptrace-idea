


#![no_std]
#![no_main]



use core::arch::asm;



#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        asm!(
            "mov edi, 0",
            "mov eax, 60",
            "syscall",
            options(nostack, noreturn)
        )
    }
}



#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
