#![no_std]
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct NeighborSolicit {
    pub router_mac: [u8; 6],
    pub router_addr: core::net::Ipv6Addr,
    pub dest_addr: core::net::Ipv6Addr,
    pub target_addr: core::net::Ipv6Addr,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    // Pod = Plan old data
    unsafe impl aya::Pod for NeighborSolicit {}
}
