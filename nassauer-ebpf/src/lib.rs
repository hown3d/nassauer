#![no_std]

use core::mem;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Icmp6Hdr {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
}

impl Icmp6Hdr {
    pub const LEN: usize = mem::size_of::<Icmp6Hdr>();
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct NeighborSolicitMessage {
    pub _reserved: u32,
    pub target_addr: [u8; 16],
}

impl NeighborSolicitMessage {
    pub const LEN: usize = mem::size_of::<NeighborSolicitMessage>();

    pub fn target_addr(&self) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from(self.target_addr)
    }
}
