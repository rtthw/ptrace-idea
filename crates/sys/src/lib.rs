


#![no_std]



mod call;

pub use call::*;



pub fn exit(status: i32) -> ! {
    call1(60, status as usize);
    unreachable!("Process continued after exiting, this should not be possible")
}
