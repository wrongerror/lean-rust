#![no_std]
#![no_main]

use aya_bpf::{BpfContext, macros::{kprobe, map}, programs::ProbeContext, maps::HashMap};
use aya_log_ebpf::info;
use aya_bpf::helpers::bpf_get_current_pid_tgid;

#[map]
static CONNECTIONS: HashMap<u32, u32> = HashMap::with_max_entries(10240, 0);

#[kprobe]
pub fn kprobetcp(ctx: ProbeContext) -> u32 {
    match try_kprobetcp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, u32> {
    let uid = bpf_get_current_uid_gid() as u32;;
    let count: u32 = unsafe { CONNECTIONS.get(&uid).unwrap_or(&0) } + 1;
    CONNECTIONS.insert(&uid, &count, 0).unwrap();
    info!(&ctx, "function tcp_connect called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
