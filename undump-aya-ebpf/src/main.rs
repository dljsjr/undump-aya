#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod kernel_bindings;

use aya_ebpf::{
    helpers::{bpf_probe_read, bpf_probe_read_buf},
    macros::{kprobe, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::ProbeContext,
    EbpfContext,
};
use aya_log_ebpf::{error, trace};
use kernel_bindings::sk_buff;
use undump_aya_common::{UdsSocketCapture, MAX_SAMPLE_DATA_BUFFER_SIZE};

const ERR_CONTEXT_READ_FAIL: i64 = 1;
const ERR_BPF_PROBE_READ_FAIL: i64 = 2;
const ERR_BPF_PROBE_READ_BUFF_FAIL: i64 = 3;
const ERR_NO_COMMAND: i64 = 4;
const ERR_NO_SAMPLE_PTR: i64 = 5;
const ERR_TOO_LARGE: i64 = 6;

#[map]
static SAMPLES: PerfEventArray<UdsSocketCapture<MAX_SAMPLE_DATA_BUFFER_SIZE>> =
    PerfEventArray::with_max_entries(128, 0);

#[map]
static NEXT_SAMPLE: PerCpuArray<UdsSocketCapture<MAX_SAMPLE_DATA_BUFFER_SIZE>> =
    PerCpuArray::with_max_entries(1, 0);

#[kprobe]
pub fn undump_aya(ctx: ProbeContext) -> u32 {
    match try_undump_aya(&ctx) {
        Ok(ret) => ret,
        Err(err_code) => {
            match err_code {
                ERR_CONTEXT_READ_FAIL => {
                    error!(&ctx, "Failed to read function args from ProbeContext")
                }
                ERR_BPF_PROBE_READ_FAIL => error!(&ctx, "bpf_probe_read failure"),
                ERR_BPF_PROBE_READ_BUFF_FAIL => error!(&ctx, "bpf_probe_read_buf failure"),
                ERR_NO_COMMAND => error!(&ctx, "no command name present"),
                ERR_TOO_LARGE => trace!(&ctx, "buffer too large"),
                code => error!(&ctx, "unknown error code {}", code),
            }
            1
        }
    }
}

fn try_undump_aya(ctx: &ProbeContext) -> Result<u32, i64> {
    unsafe {
        let sk_buff: *mut sk_buff = ctx.arg(0).ok_or(ERR_CONTEXT_READ_FAIL)?;
        let len = bpf_probe_read(&(*sk_buff).len).map_err(|_| ERR_BPF_PROBE_READ_FAIL)? as usize;
        if len > MAX_SAMPLE_DATA_BUFFER_SIZE {
            return Err(ERR_TOO_LARGE);
        }
        if let Some(evt) = NEXT_SAMPLE.get_ptr_mut(0) {
            (*evt).len = len as u32;
            (*evt).pid = ctx.pid();
            (*evt).command = ctx.command().map_err(|_| ERR_NO_COMMAND)?;

            bpf_probe_read_buf(
                bpf_probe_read(&(*sk_buff).data).map_err(|_| ERR_BPF_PROBE_READ_FAIL)?,
                &mut (*evt).buff,
            )
            .map_err(|_| ERR_BPF_PROBE_READ_BUFF_FAIL)?;
            SAMPLES.output(ctx, &*evt, 0);
        } else {
            return Err(ERR_NO_SAMPLE_PTR);
        }
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
