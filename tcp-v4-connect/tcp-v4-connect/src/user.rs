use std::io::{Write, stdout};
use std::ffi::{c_void, CString};
use aya::maps::HashMap;
use anyhow::Result;

// define the main function exported to the wasm runtime
#[no_mangle]
fn main(connections_ptr: *mut c_void) -> Result<()> {
    // get the map reference from the argument
    let connections = unsafe { HashMap::<u32, u64>::try_from(connections_ptr).unwrap() };

    // iterate over the map and print the TCP connections per process
    for (pid, count) in connections.iter() {
        let message = format!("Process {} has {} TCP connections\n", pid, count);
        let message = CString::new(message).unwrap();
        let mut handle = stdout().lock();
        writeln!(handle, "Process {} has {} TCP connections", pid, count).unwrap();
    }

    Ok(())
}