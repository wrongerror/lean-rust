#![no_std]
#![no_main]

use aya_bpf::{macros::kprobe, macros::map, programs::ProbeContext, maps::HashMap, BpfContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_v4_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map]
static CONNECTIONS: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

fn try_tcp_v4_connect(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    let count = unsafe { CONNECTIONS.get(&pid).unwrap_or(&0) } + 1;
    CONNECTIONS.insert(&pid, &count, 0).unwrap();
    info!(&ctx, "function tcp_v4_connect called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
