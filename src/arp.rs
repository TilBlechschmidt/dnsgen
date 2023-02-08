use std::{
    collections::HashMap,
    io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ipnet::{IpNet, Ipv4Net};
use libarp::{
    arp::{ArpMessage, Operation},
    client::ArpClient,
    interfaces::{Interface, MacAddr as ArpMacAddr},
};
use pnet_datalink::interfaces;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{mpsc::UnboundedSender, Notify},
    task::JoinHandle,
    time::{sleep, timeout},
};

use crate::IncomingAnnouncement;

const STAGGER: Duration = Duration::from_millis(1);

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MacAddr(pub [u8; 6]);

type Entries = Arc<Mutex<HashMap<MacAddr, (Ipv4Addr, Instant)>>>;

pub struct SubnetScanner {
    interface: Interface,
    subnet: Ipv4Net,

    ip: Ipv4Addr,
    mac: ArpMacAddr,

    entries: Entries,
    task: JoinHandle<()>,

    notifier: Arc<Notify>,
    verbose: bool,
}

impl SubnetScanner {
    pub fn new(
        subnet: Ipv4Net,
        iface_name: Option<String>,
        notifier: Arc<Notify>,
        verbose: bool,
        mirror_tx: Option<UnboundedSender<IncomingAnnouncement>>,
    ) -> io::Result<Self> {
        let iface_name = iface_name.unwrap_or(interfaces()
            .into_iter()
            .find(|iface| {
                iface.is_up()
                    && !iface.is_loopback()
                    && iface
                        .ips
                        .iter()
                        .find(|ip| IpNet::V4(subnet).contains(&ip.ip()))
                        .is_some()
            })
            .expect("failed to find network interface for ARP, either explicitly set the name or make sure that the ARP range matches one of the active network interfaces")
            .name);

        println!("Using '{iface_name}' for ARP scanning");

        let interface = Interface::new_by_name(&iface_name).unwrap();
        let ip = interface.get_ip().unwrap();
        let mac = interface.get_mac();

        let entries = Arc::new(Mutex::new(HashMap::new()));
        let task = Self::spawn_rx_task(entries.clone(), &interface, notifier.clone(), mirror_tx);

        Ok(Self {
            interface,
            subnet,

            ip,
            mac,

            entries,
            task,

            notifier,
            verbose,
        })
    }

    pub async fn sweep(&self) -> io::Result<()> {
        for ip in self.subnet.hosts() {
            let message = ArpMessage::new_arp_request(self.mac, self.ip, ip);
            message.send(&self.interface)?;
            sleep(STAGGER).await;
        }

        Ok(())
    }

    pub async fn resolve(&self, mac: MacAddr, timeout: Duration) -> io::Result<Ipv4Addr> {
        // In most cases, this does nothing as RARP is effectively dead
        // However, we should still discover the host with the next sweep
        let message = ArpMessage::new_rarp_request(self.mac, mac.into());
        message.send(&self.interface)?;

        Ok(self::timeout(timeout, self.wait_for_host(mac)).await?)
    }

    pub fn add(&self, mac: MacAddr, ip: Ipv4Addr) {
        self.entries
            .lock()
            .expect("failed to lock ARP mutex")
            .insert(mac, (ip, Instant::now()));
    }

    async fn wait_for_host(&self, mac: MacAddr) -> Ipv4Addr {
        loop {
            if let Some(ip) = self
                .entries
                .lock()
                .expect("failed to lock ARP mutex")
                .iter()
                .find(|(m, _)| **m == mac)
                .map(|(_, (ip, _))| ip)
            {
                return *ip;
            }

            self.notifier.notified().await;
        }
    }

    pub fn hosts(&self) -> Vec<(MacAddr, Ipv4Addr)> {
        self.entries
            .lock()
            .expect("failed to lock ARP mutex")
            .iter()
            .map(|(mac, (ip, _))| (*mac, *ip))
            .collect()
    }

    pub fn remove_old(&self, max_age: Duration) {
        let mut entries = self.entries.lock().expect("failed to lock ARP mutex");
        let original_len = entries.len();
        entries.retain(|mac, (ip, i)| {
            let fresh = i.elapsed() < max_age;

            if self.verbose && !fresh {
                println!("- {}.k8s.ppidev.net {ip}", MacAddr::from(*mac));
            }

            fresh
        });

        if entries.len() != original_len {
            self.notifier.notify_waiters();
            self.notifier.notify_one();
        }
    }

    fn spawn_rx_task(
        entries: Entries,
        interface: &Interface,
        notifier: Arc<Notify>,
        mirror_tx: Option<UnboundedSender<IncomingAnnouncement>>,
    ) -> JoinHandle<()> {
        let own_mac = interface.get_mac();
        let entries = entries.clone();
        let mut client = ArpClient::new_with_iface(interface).unwrap();

        tokio::spawn(async move {
            loop {
                if let Some(message) = client.receive_next().await {
                    match message.operation {
                        Operation::ArpResponse | Operation::RarpResponse => {
                            let mac = message.source_hardware_address;
                            let ip = message.source_protocol_address;

                            if mac == own_mac {
                                continue;
                            }

                            if let Some(tx) = mirror_tx.as_ref() {
                                if tx
                                    .send(IncomingAnnouncement::Arp(crate::ArpDiscovery {
                                        mac: mac.into(),
                                        ip,
                                    }))
                                    .is_err()
                                {
                                    eprintln!("Mirroring TX has been closed!");
                                }
                            }

                            let old_entry = entries
                                .lock()
                                .expect("failed to lock ARP mutex")
                                .insert(mac.into(), (ip, Instant::now()));

                            match old_entry {
                                None => {
                                    println!("+ {} {ip}", MacAddr::from(mac));
                                    notifier.notify_waiters();
                                    notifier.notify_one();
                                }
                                Some((old_ip, _)) if old_ip != ip => {
                                    println!("~ {} {ip}", MacAddr::from(mac));
                                    notifier.notify_waiters();
                                    notifier.notify_one();
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                } else {
                    sleep(STAGGER).await;
                }
            }
        })
    }
}

impl Drop for SubnetScanner {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl From<ArpMacAddr> for MacAddr {
    fn from(value: ArpMacAddr) -> Self {
        Self([value.0, value.1, value.2, value.3, value.4, value.5])
    }
}

impl From<MacAddr> for ArpMacAddr {
    fn from(value: MacAddr) -> Self {
        Self(
            value.0[0], value.0[1], value.0[2], value.0[3], value.0[4], value.0[5],
        )
    }
}

impl TryFrom<String> for MacAddr {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut bytes = [0; 6];
        let mut read = 0;

        for (i, digit) in value.split(":").enumerate() {
            if i < 6 {
                bytes[i] = u8::from_str_radix(digit, 16).map_err(|e| e.to_string())?;
            }
            read += 1;
        }

        match read {
            6 => Ok(Self(bytes)),
            _ => Err("invalid number of hex digits".into()),
        }
    }
}

impl From<MacAddr> for String {
    fn from(value: MacAddr) -> Self {
        value.to_string()
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}
