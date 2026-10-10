//! The N-API entry points the native-binding test binary references, defined as one object file
//! for the test link. A test binary is not loaded by Node and no test calls into N-API; each
//! function here ends the process with a message naming the symbol if one ever is called.
//!
//! The file is compiled on its own by `//sdk/typescript:napi_host_stub`, with `no_std` and only
//! `write` and `abort` from the C library, so it depends on nothing of the crates it stands in for.
#![no_std]

extern "C" {
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn abort() -> !;
}

macro_rules! napi_host_stub {
    ($($name:ident),+ $(,)?) => {$(
        // The symbol carries the N-API name unmangled so the linker resolves the binding's
        // references to it; its signature is never used, since it does not return.
        #[no_mangle]
        pub extern "C" fn $name() -> ! {
            let message = concat!(stringify!($name), ": N-API is provided by the Node host, not by the test binary\n");
            // SAFETY: `write` reads `message.len()` bytes from a live static string, and `abort`
            // takes no arguments and never returns.
            unsafe {
                write(2, message.as_ptr(), message.len());
                abort()
            }
        }
    )+};
}

napi_host_stub!(napi_call_threadsafe_function, napi_delete_reference, napi_reference_unref);
