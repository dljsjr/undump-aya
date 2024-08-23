use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{debug, info, warn};
use tokio::signal;
use undump_aya_common::{UdsSocketCapture, MAX_SAMPLE_DATA_BUFFER_SIZE};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/undump-aya"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/undump-aya"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut KProbe = bpf.program_mut("undump_aya").unwrap().try_into()?;
    program.load()?;
    program.attach("unix_stream_read_actor", 0)?;

    println!(
        "{:<8} {:<16} {:<8} {:<8} {:<}",
        "TIME", "COMM", "PID", "SIZE", "DATA"
    );

    let bytes_per_sample = core::mem::size_of::<UdsSocketCapture<MAX_SAMPLE_DATA_BUFFER_SIZE>>();
    println!("bytes per sample: {bytes_per_sample}");
    let mut samples_array = AsyncPerfEventArray::try_from(bpf.take_map("SAMPLES").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut sample_buffer = samples_array.open(cpu_id, None)?;

        tokio::task::spawn(async move {
            let mut raw_buffers = (0..32)
                .map(|_| BytesMut::with_capacity(bytes_per_sample * 2))
                .collect::<Vec<_>>();

            loop {
                let sample = sample_buffer.read_events(&mut raw_buffers).await.unwrap();
                for buf in raw_buffers.iter_mut().take(sample.read) {
                    let sample_ptr =
                        buf.as_ptr() as *const UdsSocketCapture<MAX_SAMPLE_DATA_BUFFER_SIZE>;
                    let sample = unsafe { sample_ptr.read_unaligned() };
                    let time = chrono::Local::now().time();
                    let command_str = String::from_utf8_lossy(&sample.command);
                    let command_str = command_str.trim_end_matches(char::from(0));
                    let data_str = String::from_utf8_lossy(&sample.buff[..sample.len as usize]);

                    println!(
                        "{} {:<16} {:<8} {:<8} {}",
                        time.format("%H:%M:%S"),
                        command_str,
                        format!("{}", sample.pid),
                        format!("{}", sample.len),
                        format!("{data_str:x?}")
                    );
                }
            }
        });
    }

    info!("\nWaiting for Ctrl-C...\n");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
