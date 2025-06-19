use std::ptr;

use anyhow::anyhow;
use aya::{
    maps::{MapData, RingBuf},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{debug, error, info};
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

    let mut responder = NeighborSolicitationResponder::new(&mut bpf)?;

    tokio::spawn(async move {
        responder.run(cloned_token).await;
    });

    wait_for_signal().await;
    token.cancel();

    info!("Exiting...");
    Ok(())
}

struct NeighborSolicitationResponder {
    ring_buf_fd: AsyncFd<RingBuf<MapData>>,
}

impl NeighborSolicitationResponder {
    fn new(bpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = bpf
            .take_map("SOLICIT")
            .ok_or(anyhow!("missing bpf map SOLICIT"))?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = AsyncFd::new(ring_buf)?;
        Ok(NeighborSolicitationResponder {
            ring_buf_fd: async_fd,
        })
    }

    async fn run(&mut self, token: CancellationToken) {
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    break;
                }
                res = self.read_solicitiation() => {
                    match res {
                        Ok(opt) => {
                            if let Some(solict) = opt {
                                info!("Received solicitation: {solict:?}")
                            }
                        }
                        Err(err) => {
                            error!("receiving solicitation: {err}")
                        }
                    };
                }
            }
        }
    }

    async fn read_solicitiation(&mut self) -> Result<Option<NeighborSolicit>, anyhow::Error> {
        let mut guard = self.ring_buf_fd.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();
        if let Some(item) = ring_buf.next() {
            let solicit = unsafe { ptr::read_unaligned(item.as_ptr() as *const NeighborSolicit) };
            return Ok(Some(solicit));
        }
        Ok(None)
    }
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    // Infos here:
    // https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
    let mut signal_terminate = signal(SignalKind::terminate()).unwrap();
    let mut signal_interrupt = signal(SignalKind::interrupt()).unwrap();

    tokio::select! {
        _ = signal_terminate.recv() => info!("Received SIGTERM."),
        _ = signal_interrupt.recv() => info!("Received SIGINT."),
    };
}
