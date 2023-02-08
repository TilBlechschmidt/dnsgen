use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, num::ParseIntError, time::Duration};

mod arp;
mod store;

pub use arp::{MacAddr, SubnetScanner};
pub use store::AnnouncementStore;

pub type FQDN = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Announcement {
    pub fqdn: FQDN,
    pub ip: Ipv4Addr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArpDiscovery {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum IncomingAnnouncement {
    Domain(Announcement),
    Arp(ArpDiscovery),
}

/// Parses a Duration from a string containing seconds.
/// Useful for command line parsing
pub fn parse_seconds(src: &str) -> Result<Duration, ParseIntError> {
    let seconds = src.parse::<u64>()?;
    Ok(Duration::from_secs(seconds))
}
