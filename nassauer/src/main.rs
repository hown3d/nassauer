use std::{ptr, u8};

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
use pnet::{
    datalink::{self, DataLinkSender, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        icmpv6::{
            self,
            ndp::{
                self, MutableNdpOptionPacket, MutableNeighborAdvertPacket, NdpOptionPacket,
                NdpOptionTypes, NeighborAdvertPacket,
            },
            Icmpv6Packet, Icmpv6Types,
        },
        ip::IpNextHeaderProtocols,
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        MutablePacket, Packet,
    },
    util::MacAddr,
};
use tokio::io::unix::AsyncFd; // (1)
use tokio_util::sync::CancellationToken;

const PKT_ETH_SIZE: usize = EthernetPacket::minimum_packet_size();
const PKT_IP6_SIZE: usize = Ipv6Packet::minimum_packet_size();
const PKT_NDP_ADV_SIZE: usize = NeighborAdvertPacket::minimum_packet_size();
const PKT_OPT_SIZE: usize = NdpOptionPacket::minimum_packet_size();
const PKT_MAC_SIZE: usize = 6;

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

    let binding = pnet::datalink::interfaces();
    let iface = match binding.into_iter().find(|iface| iface.name == opt.iface) {
        Some(i) => i,
        None => return Err(anyhow!("interface {} not found", opt.iface)),
    };

    let mut responder = NeighborSolicitationResponder::new(&mut bpf, iface)?;

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
    host_mac: MacAddr,
    tx: Box<dyn DataLinkSender>,
}

impl NeighborSolicitationResponder {
    fn new(bpf: &mut Ebpf, iface: NetworkInterface) -> Result<Self, anyhow::Error> {
        let (tx, _) = match pnet::datalink::channel(&iface, datalink::Config::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow!("recieved unknown channel")),
            Err(e) => return Err(anyhow!(e)),
        };

        let mac = iface.mac.ok_or(anyhow!(
            "unable to retrive mac address for interface {}",
            &iface.name
        ))?;

        debug!("using mac address {mac} as host_mac");

        let map = bpf
            .take_map("SOLICIT")
            .ok_or(anyhow!("missing bpf map SOLICIT"))?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = AsyncFd::new(ring_buf)?;

        Ok(NeighborSolicitationResponder {
            ring_buf_fd: async_fd,
            tx,
            host_mac: mac,
        })
    }

    async fn run(&mut self, token: CancellationToken) {
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    break;
                }
                res = self.respond() => {
                    if let Err(err) = res {
                        error!("error responding: {err:?}")
                    }
                }
            }
        }
    }

    async fn respond(&mut self) -> Result<(), anyhow::Error> {
        if let Some(solicit) = self.read_solicitiation().await? {
            let packet_vec = self.build_packet(solicit)?;
            self.tx
                .send_to(&packet_vec, None)
                .unwrap()
                .map_err(|e| anyhow!(e))?;
            info!("sent NDP advert packet for {solicit:?}")
        };
        Ok(())
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

    fn build_packet(&self, solicit: NeighborSolicit) -> Result<Vec<u8>, anyhow::Error> {
        const TARGET_LL_ADDR_NDP_OPTION_SIZE: usize = PKT_OPT_SIZE + PKT_MAC_SIZE;
        const TOTAL_PACKET_SIZE: usize =
            PKT_ETH_SIZE + PKT_IP6_SIZE + PKT_NDP_ADV_SIZE + TARGET_LL_ADDR_NDP_OPTION_SIZE;

        let mut packet_buf = [0u8; TOTAL_PACKET_SIZE];

        let mut eth_packet = MutableEthernetPacket::new(&mut packet_buf).unwrap();
        eth_packet.set_destination(MacAddr::from(solicit.router_mac.octets()));
        eth_packet.set_source(self.host_mac);
        eth_packet.set_ethertype(EtherTypes::Ipv6);

        debug!("ethernet packet: {eth_packet:?}");

        let mut ip6_packet = MutableIpv6Packet::new(eth_packet.payload_mut()).unwrap();
        ip6_packet.set_version(0x06);
        ip6_packet.set_payload_length(
            (PKT_NDP_ADV_SIZE + PKT_OPT_SIZE + PKT_MAC_SIZE)
                .try_into()
                .unwrap(),
        );
        ip6_packet.set_source(solicit.target_addr);
        ip6_packet.set_destination(solicit.router_addr);
        ip6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ip6_packet.set_hop_limit(u8::MAX);
        debug!("ipv6 packet: {ip6_packet:?}");

        let mut adv_packet = MutableNeighborAdvertPacket::new(ip6_packet.payload_mut()).unwrap();
        adv_packet.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
        adv_packet.set_icmpv6_code(ndp::Icmpv6Codes::NoCode);
        adv_packet.set_target_addr(solicit.target_addr);
        let mut adv_flags = ndp::NeighborAdvertFlags::Router | ndp::NeighborAdvertFlags::Solicited;
        if solicit.dest_addr.is_multicast() {
            adv_flags |= ndp::NeighborAdvertFlags::Override
        }
        adv_packet.set_flags(adv_flags);

        let mut opt_packet = MutableNdpOptionPacket::new(adv_packet.get_options_raw_mut())
            .ok_or(anyhow!("unable to build ndp option packet"))?;
        opt_packet.set_option_type(NdpOptionTypes::TargetLLAddr);
        let mac_octects = self.host_mac.octets();
        // Length is in units of 8 octets. (1 for type, 1 for len, 6 for MAC) = 8 bytes = 1 unit.
        opt_packet.set_length(1);
        // It is necessary to first set the length, otherwise assertion will fail that the
        // length field is smaller then the data length
        opt_packet.set_data(&mac_octects);

        // Set the checksum (part of the NDP packet)
        adv_packet.set_checksum(icmpv6::checksum(
            &Icmpv6Packet::new(adv_packet.packet()).unwrap(),
            &solicit.target_addr,
            &solicit.router_addr,
        ));
        debug!("ndp advert packet: {adv_packet:?}");

        Ok(Vec::from(packet_buf))
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
