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
use tokio::{sync::Notify, task::JoinHandle, time::sleep};

const STAGGER: Duration = Duration::from_millis(1);

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
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
        let task = Self::spawn_rx_task(entries.clone(), &interface, notifier.clone());

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
        }
    }

    fn spawn_rx_task(
        entries: Entries,
        interface: &Interface,
        notifier: Arc<Notify>,
    ) -> JoinHandle<()> {
        let entries = entries.clone();
        let mut client = ArpClient::new_with_iface(interface).unwrap();

        tokio::spawn(async move {
            loop {
                if let Some(message) = client.receive_next().await {
                    if message.operation == Operation::ArpResponse {
                        let mac = message.source_hardware_address;
                        let ip = message.source_protocol_address;

                        let old_entry = entries
                            .lock()
                            .expect("failed to lock ARP mutex")
                            .insert(mac.into(), (ip, Instant::now()));

                        match old_entry {
                            None => {
                                println!("+ {}.k8s.ppidev.net {ip}", MacAddr::from(mac));
                                notifier.notify_one();
                            }
                            Some((old_ip, _)) if old_ip != ip => {
                                println!("~ {}.k8s.ppidev.net {ip}", MacAddr::from(mac));
                                notifier.notify_one();
                            }
                            _ => {}
                        }
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

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}