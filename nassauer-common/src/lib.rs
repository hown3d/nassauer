#![no_std]

use core::fmt;

// use pnet_base::MacAddr;
#[derive(fmt::Debug, Copy, Clone)]
#[repr(C)]
pub struct NeighborSolicit {
    // pub router_mac: MacAddr,
    pub router_mac: MacAddr,
    pub router_addr: core::net::Ipv6Addr,
    pub dest_addr: core::net::Ipv6Addr,
    pub target_addr: core::net::Ipv6Addr,
}

// This is a small implementation derived from pnet_base's MacAddr.
// Since the no_std change in pnet_base is not yet released, copy the implementation to have a nice
// fmt::Display implementation
#[derive(PartialEq, Eq, Clone, Copy, Default, Hash, Ord, PartialOrd)]
#[repr(C)]
pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    /// Construct a new `MacAddr` instance.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr(a, b, c, d, e, f)
    }

    /// Returns the six eight-bit integers that make up this address
    pub fn octets(&self) -> [u8; 6] {
        [self.0, self.1, self.2, self.3, self.4, self.5]
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(addr: [u8; 6]) -> MacAddr {
        MacAddr(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0, self.1, self.2, self.3, self.4, self.5
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    // Pod = Plan old data
    unsafe impl aya::Pod for NeighborSolicit {}
}
