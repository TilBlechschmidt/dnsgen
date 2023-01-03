use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, num::ParseIntError, time::Duration};

mod store;
pub use store::AnnouncementStore;

pub type FQDN = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Announcement {
    pub fqdn: FQDN,
    pub ip: Ipv4Addr,
}

/// Parses a Duration from a string containing seconds.
/// Useful for command line parsing
pub fn parse_seconds(src: &str) -> Result<Duration, ParseIntError> {
    let seconds = src.parse::<u64>()?;
    Ok(Duration::from_secs(seconds))
}
