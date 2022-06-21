use super::{Announcement, FQDN};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

pub struct AnnouncementStore {
    mappings: HashMap<FQDN, HashMap<Ipv4Addr, Instant>>,
    threshold: Duration,
    verbose: bool,
}

impl AnnouncementStore {
    pub fn new(threshold: Duration, verbose: bool) -> Self {
        Self {
            mappings: HashMap::new(),
            threshold,
            verbose,
        }
    }

    // Adds the IP to the store or refreshes an existing entry. Returns true if it was not present before
    pub fn add(&mut self, announcement: Announcement) -> bool {
        let did_add = self
            .mappings
            .entry(announcement.fqdn.clone())
            .or_default()
            .insert(announcement.ip, Instant::now())
            .is_none();

        if self.verbose && did_add {
            println!("+ {} {}", announcement.fqdn, announcement.ip);
        }

        did_add
    }

    /// Removes stale entries from the store
    pub fn purge_old(&mut self) -> usize {
        let mut empty_hostnames = Vec::new();

        // Go through all hostnames
        let mut purged = 0;
        for (hostname, entries) in self.mappings.iter_mut() {
            let previous_len = entries.len();

            // Remove all IP entries that are too old
            entries.retain(|ip, timestamp| {
                let age = Instant::now() - *timestamp;
                let fresh = age < self.threshold;

                if self.verbose && !fresh {
                    println!("- {} {}", hostname, ip);
                }

                fresh
            });

            purged += previous_len - entries.len();

            // Track empty hostname arrays
            if entries.is_empty() {
                empty_hostnames.push(hostname.clone());
            }
        }

        // Purge hostnames w/o IPs so we don't leak any memory
        for hostname in empty_hostnames.into_iter() {
            println!("- {}", hostname);
            self.mappings.remove(&hostname);
        }

        purged
    }

    /// Lists all currently stored entries. Note that some might be stale if you did not call `purge_old` recently.
    pub fn entries(&self) -> HashMap<&FQDN, Vec<&Ipv4Addr>> {
        self.mappings
            .iter()
            .map(|(hostname, ips)| (hostname, ips.keys().collect()))
            .collect()
    }
}
