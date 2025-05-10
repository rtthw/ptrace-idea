


#![no_std]
#![no_main]



#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::call1(60, 0);
    loop {}
}



#[cfg(not(test))]
#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
