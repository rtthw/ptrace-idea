


#![no_std]
#![no_main]



#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::call0(sys::SYS_CUSTOM as _);
    sys::exit(0)
}



#[cfg(not(test))]
#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
