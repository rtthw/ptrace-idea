


#![no_std]



mod call;

pub use call::*;



pub const SYS_CUSTOM: u64 = 292001;



unsafe extern "C" {
    #[link_name = "__errno_location"]
    pub fn errno_location() -> *mut core::ffi::c_int;
}

#[inline]
pub fn errno() -> i32 {
    unsafe { (*errno_location()) as i32 }
}



pub fn exit(status: i32) -> ! {
    call1(60, status as usize);
    unreachable!("Process continued after exiting, this should not be possible")
}
