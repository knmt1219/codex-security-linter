pub unsafe fn dangerous_operation(ptr: *mut i32) {
    unsafe {
        *ptr = 1337;
    }
}
