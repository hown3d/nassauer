#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use aya_log_ebpf::info;
use nassauer_common::NeighborSolicit;
use nassauer_ebpf::{Icmp6Hdr, NeighborSolicitMessage};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv6Hdr},
};

const ICMP_NEIGHBOR_SOLICITATION_TYPE: u8 = 135;

#[no_mangle]
static VERSION: i32 = 0;

#[map]
static SOLICIT: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[classifier]
pub fn nassauer(ctx: TcContext) -> i32 {
    match try_nassauer(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_nassauer(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match eth_hdr.ether_type {
        EtherType::Ipv6 => (),
        _ => return Ok(TC_ACT_OK),
    }

    let ip_hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    match ip_hdr.next_hdr {
        IpProto::Ipv6Icmp => (),
        _ => return Ok(TC_ACT_OK),
    }

    let icmp_hdr: Icmp6Hdr = ctx.load(EthHdr::LEN + Ipv6Hdr::LEN).map_err(|_| ())?;
    match icmp_hdr.type_ {
        ICMP_NEIGHBOR_SOLICITATION_TYPE => (),
        _ => return Ok(TC_ACT_OK),
    }
    info!(&ctx, "icmp type is neighbor soliticitation");

    let neighbor_solicit_msg: NeighborSolicitMessage = ctx
        .load(EthHdr::LEN + Ipv6Hdr::LEN + Icmp6Hdr::LEN)
        .map_err(|_| ())?;

    let target_addr = neighbor_solicit_msg.target_addr();
    let ns = NeighborSolicit {
        target_addr,
        dest_addr: ip_hdr.dst_addr(),
        router_addr: ip_hdr.src_addr(),
        router_mac: eth_hdr.src_addr,
    };
    if let Some(mut buf) = SOLICIT.reserve::<NeighborSolicit>(0) {
        buf.write(ns);
        unsafe {
            buf.assume_init();
        }
        buf.submit(0);
    }

    Ok(TC_ACT_SHOT)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
