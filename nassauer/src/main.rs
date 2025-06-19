use std::ptr;

use anyhow::anyhow;
use aya::{
    maps::{Map, MapData, RingBuf},
    programs::{tc, SchedClassifier, TcAttachType},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{debug, info};
use nassauer_common::NeighborSolicit;
use tokio::io::unix::AsyncFd; // (1)
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String, // (2)
}

#[tokio::main] // (3)
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        "../../target/bpfel-unknown-none/release/nassauer-ebpf"
    )))?;

    EbpfLogger::init(&mut bpf)?;
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = match bpf.program_mut("nassauer") {
        Some(prog) => prog.try_into()?,
        None => return Err(anyhow!("nassauer program missing in ebpf")),
    };
    info!("loading ebpf program");
    program.load()?;
    info!("attaching program to {}", &opt.iface);
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    // Step 1: Create a new CancellationToken
    let token = CancellationToken::new();

    // Step 2: Clone the token for use in another task
    let cloned_token = token.clone();

    let ring_handle = tokio::spawn(async move {
        let map = match bpf.map_mut("SOLICIT") {
            Some(m) => m,
            None => return Err(anyhow!("missing bpf map SOLICIT")),
        };
        let ring_buf = RingBuf::try_from(map)?;
        tokio::select! {
            // Step 3: Using cloned token to listen to cancellation requests
            _ = cloned_token.cancelled() => {
                return Err(anyhow!("token canceled"))
            }
            res = read_solicitiations(ring_buf)  => {
                match res {
                    Ok(_) => Ok(()),
                    Err(e) => return Err(e),
                }
            }
        }
    });

    tokio::select! {
    _ = wait_for_signal() => {
    info!("signal exit completed");
        token.cancel();

        }
        res = ring_handle => match res {
        Ok(res) => match res {
            Ok(_) => (),
            Err(e) => return Err(anyhow!(e)),
        },
        Err(e) => return Err(anyhow!(e)),
        }
        }

    info!("Exiting...");

    Ok(())
}

async fn read_solicitiations(ring_buf: RingBuf<&mut MapData>) -> Result<(), anyhow::Error> {
    let mut async_fd = AsyncFd::new(ring_buf)?;
    loop {
        let mut guard = async_fd.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();
        while let Some(item) = ring_buf.next() {
            let solicit = unsafe { ptr::read_unaligned(item.as_ptr() as *const NeighborSolicit) };
            info!("retrieved neighbor solicitation {:?}", solicit)
        }
    }
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    // Infos here:
    // https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
    let mut signal_terminate = signal(SignalKind::terminate()).unwrap();
    let mut signal_interrupt = signal(SignalKind::interrupt()).unwrap();

    tokio::select! {
        _ = signal_terminate.recv() => debug!("Received SIGTERM."),
        _ = signal_interrupt.recv() => debug!("Received SIGINT."),
    };
}
