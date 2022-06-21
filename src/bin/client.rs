use dnsgen::{parse_seconds, Announcement};
use ipnetwork::{IpNetwork, Ipv4Network};
use pnet_datalink::interfaces;
use reqwest::blocking::Response;
use std::{net::Ipv4Addr, thread::sleep, time::Duration};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct ClientOptions {
    /// Filter for the subnet in which IPs should be discovered, in CIDR notation (e.g. 10.0.0.0/16).
    #[structopt(long)]
    subnet: Ipv4Network,

    /// How often to advertise in seconds.
    #[structopt(short, long, default_value = "120", parse(try_from_str = parse_seconds))]
    interval: Duration,

    /// Where to advertise to, HTTP URL including protocol.
    #[structopt(long)]
    server: String,

    /// Domain to advertise (e.g. 'hello-world.example.com'). Note that the server has to allow this domain.
    fqdn: String,
}

fn find_ips(subnet: Ipv4Network) -> impl Iterator<Item = Ipv4Addr> {
    interfaces()
        .into_iter()
        .map(|i| i.ips)
        .flatten()
        .filter_map(|network| match network {
            IpNetwork::V4(network) => Some(network.ip()),
            _ => None,
        })
        .filter(move |ip| subnet.contains(*ip))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = ClientOptions::from_args();

    println!(
        "Announcing local interface IPs in subnet {} as '{}' every {} secs to {}",
        options.subnet,
        options.fqdn,
        options.interval.as_secs(),
        options.server
    );

    println!(
        "Current IPs: {:?}",
        find_ips(options.subnet).collect::<Vec<_>>()
    );

    let client = reqwest::blocking::Client::new();

    loop {
        for ip in find_ips(options.subnet) {
            let announcement = Announcement {
                fqdn: options.fqdn.clone(),
                ip,
            };

            match client
                .post(&options.server)
                .json(&announcement)
                .send()
                .map(Response::error_for_status)
            {
                Ok(Err(err)) => eprintln!("failed announcing {ip}: announcement rejected: {err}"),
                Err(err) => eprintln!("failed announcing {ip}: http request failed: {err}"),
                _ => (),
            }
        }

        sleep(options.interval);
    }
}
