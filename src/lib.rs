#![no_std]

extern crate alloc;
pub mod llc;
pub mod geo_networking;
pub mod security;
pub mod util;

pub use ieee80211;

pub const WILDCARD_MAC_ADDRESS: ieee80211::mac_parser::MACAddress = ieee80211::mac_parser::MACAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
pub const GEO_NETWORKING_ETHERTYPE: u16 = 0x8947;

pub mod asn {
    include!(concat!(env!("OUT_DIR"), "/cam_denm.rs"));
    include!(concat!(env!("OUT_DIR"), "/ivim.rs"));
    include!(concat!(env!("OUT_DIR"), "/mapem.rs"));
    include!(concat!(env!("OUT_DIR"), "/spatem.rs"));
    include!(concat!(env!("OUT_DIR"), "/efc.rs"));
    include!(concat!(env!("OUT_DIR"), "/gdd.rs"));
    // include!(concat!(env!("OUT_DIR"), "/1609dot2.rs"));
    include!("../asn_rs/ts_102941.rs");
}