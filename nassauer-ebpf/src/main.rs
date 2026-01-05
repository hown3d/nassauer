#![no_std]
#![no_main]

use core::net::Ipv6Addr;

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    btf_maps::RingBuf,
    macros::{btf_map, classifier, map},
    maps::{lpm_trie, LpmTrie},
    programs::TcContext,
};
use aya_log_ebpf::{debug, info};
use nassauer_common::{MacAddr, NeighborSolicit};
use nassauer_ebpf::{Icmp6Hdr, NeighborSolicitMessage};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv6Hdr},
};

const ICMP_NEIGHBOR_SOLICITATION_TYPE: u8 = 135;

#[no_mangle]
static VERSION: i32 = 0;

#[map]
static IPV6_PREFIXES: LpmTrie<Ipv6Addr, u8> = LpmTrie::with_max_entries(1024, 0);

#[btf_map]
static SOLICIT: RingBuf<nassauer_common::NeighborSolicit, { 256 * 1024 }, 0> = RingBuf::new();

#[classifier]
pub fn nassauer(ctx: TcContext) -> i32 {
    debug!(&ctx, "retrieved packet");
    match try_nassauer(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_nassauer(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match eth_hdr.ether_type {
        EtherType::Ipv6 => (),
        _ => {
            debug!(&ctx, "ethHdr ether_type is not ipv6");
            return Ok(TC_ACT_OK);
        }
    }

    let ip_hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    match ip_hdr.next_hdr {
        IpProto::Ipv6Icmp => (),
        _ => {
            debug!(&ctx, "ipv6Hdr next_hdr is not Ipv6Icmp");
            return Ok(TC_ACT_OK);
        }
    }

    let icmp_hdr: Icmp6Hdr = ctx.load(EthHdr::LEN + Ipv6Hdr::LEN).map_err(|_| ())?;
    match icmp_hdr.type_ {
        ICMP_NEIGHBOR_SOLICITATION_TYPE => (),
        _ => {
            debug!(&ctx, "icmp6Hdr type is not neighbor solicitation");
            return Ok(TC_ACT_OK);
        }
    }
    info!(&ctx, "icmp type is neighbor soliticitation");

    let neighbor_solicit_msg: NeighborSolicitMessage = ctx
        .load(EthHdr::LEN + Ipv6Hdr::LEN + Icmp6Hdr::LEN)
        .map_err(|_| ())?;

    let target_addr = neighbor_solicit_msg.target_addr();

    // Create the key for the LPM lookup.
    // The prefix length must be the maximum possible (128 for IPv6)
    // to find the *longest matching* prefix.
    // Perform the lookup in the LPM map
    let key = lpm_trie::Key::new(128, target_addr);
    info!(&ctx, "checking lpm trie for address {}", target_addr);
    if IPV6_PREFIXES.get(&key).is_some() {
        info!(&ctx, "Matched IP {}", target_addr);
        let ns = NeighborSolicit {
            target_addr,
            dest_addr: ip_hdr.dst_addr(),
            router_addr: ip_hdr.src_addr(),
            router_mac: MacAddr::from(eth_hdr.src_addr),
        };
        if let Some(mut buf) = SOLICIT.reserve(0) {
            buf.write(ns);
            unsafe {
                buf.assume_init();
            }
            buf.submit(0);
        }
    }

    Ok(TC_ACT_SHOT)
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
