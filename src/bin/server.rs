use dnsgen::{parse_seconds, Announcement, AnnouncementStore, SubnetScanner};
use ipnet::Ipv4Net;
use reqwest::{Client, StatusCode, Url};
use std::{io, path::PathBuf, sync::Arc, time::Duration};
use structopt::StructOpt;
use tokio::{
    fs,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex, Notify,
    },
    task,
    time::sleep,
};
use warp::{reply, Filter};

/// Header which prevents further mirroring of requests when set to "true"
/// (stops infinite forwarding loops)
const HEADER_DNSGEN_MIRROR: &str = "X-DNSGEN-MIRRORED";

#[derive(StructOpt, Debug)]
struct ServerOptions {
    /// How often to check for and purge stale announcements
    #[structopt(long, default_value = "60", parse(try_from_str = parse_seconds))]
    purge_interval: Duration,

    /// Time after which an announcement is considered stale
    #[structopt(long, default_value = "300", parse(try_from_str = parse_seconds))]
    max_age: Duration,

    /// HTTP port to listen on
    #[structopt(long, default_value = "3030")]
    port: u16,

    /// Prints added/removed IPs and domains
    #[structopt(short, long)]
    verbose: bool,

    /// Domain prefix for which subdomains should be allowed
    domain: String,

    /// Location to store the zone file at
    zone_file: PathBuf,

    /// Where the authoritive nameserver for the given domain can be found
    #[structopt(short, long)]
    authoritive_nameserver: String,

    /// Path to a file containing a whitespace separated list of IPs to where incoming request shall be mirrored
    mirror: Option<PathBuf>,

    /// Subnet to scan for devices
    ///
    /// If set, dnsgen will occasionally sweep the subnet with ARP messages to find any MAC->IP associations
    /// for which A-records will be created.
    ///
    /// NOTE: This requires actively listening in to all Ethernet traffic which uses a good amount of CPU!
    #[structopt(long)]
    arp_net: Option<Ipv4Net>,

    /// Interval of subnet scans, see arp_net for more details
    #[structopt(long, default_value = "30", parse(try_from_str = parse_seconds))]
    arp_interval: Duration,

    /// Optionally specify the interface on which scans should be performed
    ///
    /// If not set, the interface will be inferred based on the subnet.
    arp_interface_name: Option<String>,
}

/// Waits for changes on the given notifier and generates a new config every time it gets notified
async fn config_update_loop(
    store: Arc<Mutex<AnnouncementStore>>,
    notifier: Arc<Notify>,
    scanner: Option<Arc<SubnetScanner>>,
    domain: String,
    authoritive_nameserver: String,
    path: PathBuf,
) {
    let root_domain_len = domain.len() + 1; // +1 to include the `.` in front of the domain name
    let mut zone_serial = 0;

    loop {
        let bytes = {
            let store = store.lock().await;
            let entries = store.entries();

            // For more details on zone file formatting and what the mandatory SOA entry is all about, see:
            // https://help.dyn.com/how-to-format-a-zone-file/

            let mut zone_file: String = format!(
                "@               30 SOA {authoritive_nameserver: >16}. zone-admin.{domain}. {zone_serial} 30 25 604800 30\n"
            );

            for (host, ips) in entries {
                let subdomain = &host[..host.len() - root_domain_len];
                for ip in ips {
                    zone_file += &format!("{subdomain: <16} 10 A {ip: >16}\n");
                }
            }

            if let Some(scanner) = scanner.as_ref() {
                for (mac, ip) in scanner.hosts() {
                    zone_file += &format!("{mac: <16} 10 A {ip: >16}\n")
                }
            }

            zone_file.into_bytes()
        };

        if let Err(err) = fs::write(&path, bytes).await {
            eprintln!("Failed to write zone file: {err}");
        }

        zone_serial += 1;
        notifier.notified().await;
    }
}

/// Purges old entries every `PURGE_INTERVAL_SEC` and sends notifications if changes have been made
async fn cleanup_loop(
    store: Arc<Mutex<AnnouncementStore>>,
    notifier: Arc<Notify>,
    interval: Duration,
) {
    loop {
        sleep(interval).await;

        if store.lock().await.purge_old() > 0 {
            notifier.notify_waiters();
        }
    }
}

/// Retrieves a list of URLs from a file on disk
async fn fetch_mirroring_endpoints(path: &PathBuf) -> Result<Vec<Url>, io::Error> {
    Ok(fs::read_to_string(path)
        .await?
        .split_whitespace()
        .filter_map(|s| match Url::parse(&format!("http://{}", s)) {
            Ok(url) => Some(url),
            Err(error) => {
                eprintln!("Failed to parse URL from mirroring file: {error}");
                None
            }
        })
        .collect())
}

/// Mirrors requests to other instances of dnsgen
async fn mirroring_loop(mut rx: UnboundedReceiver<Announcement>, path: PathBuf) {
    let client = Client::new();

    while let Some(announcement) = rx.recv().await {
        let endpoints = fetch_mirroring_endpoints(&path).await.unwrap();

        for endpoint in endpoints {
            let response = client
                .post(endpoint.clone())
                .json(&announcement)
                .header(HEADER_DNSGEN_MIRROR, "true")
                .send();

            if let Err(err) = response.await {
                eprintln!("Failed to mirror to {endpoint}: {err}");
            }
        }
    }
}

/// Scans the local subnet every now and then
async fn arp_scan_loop(scanner: Arc<SubnetScanner>, interval: Duration) {
    loop {
        if let Err(err) = scanner.sweep().await {
            eprintln!("Failed to do ARP scan {err:?}");
        }

        scanner.remove_old(interval * 2);
        sleep(interval).await;
    }
}

/// Stores announcements received via HTTP POST in the given store and sends notifications each time it does so
async fn http_server(
    store: Arc<Mutex<AnnouncementStore>>,
    notifier: Arc<Notify>,
    port: u16,
    domain: String,
    mirror_tx: Option<UnboundedSender<Announcement>>,
) {
    let store_ref = store.clone();

    let receiver = warp::post()
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::json())
        .and(warp::header::optional(HEADER_DNSGEN_MIRROR))
        .then(move |announcement: Announcement, mirrored: Option<bool>| {
            let store = store_ref.clone();
            let notifier = notifier.clone();
            let domain = domain.clone();
            let mirror_tx = mirror_tx.clone();

            async move {
                if !announcement.fqdn.ends_with(&domain) {
                    warp::reply::with_status(
                        "Domain name suffix not allowed",
                        StatusCode::UNAUTHORIZED,
                    )
                } else {
                    let mut store = store.lock().await;

                    if !mirrored.unwrap_or_default() {
                        if let Some(tx) = mirror_tx {
                            println!("mirroring request");
                            if tx.send(announcement.clone()).is_err() {
                                eprintln!("Mirroring TX has been closed!");
                            }
                        }
                    }

                    if store.add(announcement) {
                        notifier.notify_waiters();
                    }

                    warp::reply::with_status("OK", StatusCode::OK)
                }
            }
        });

    let query = warp::get().then(move || {
        let store = store.clone();
        async move { reply::json(&store.lock().await.entries()) }
    });

    let routes = query.or(receiver);

    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}

#[tokio::main]
async fn main() {
    let options = ServerOptions::from_args();

    let notifier = Arc::new(Notify::new());
    let store = Arc::new(Mutex::new(AnnouncementStore::new(
        options.max_age,
        options.verbose,
    )));

    let mirror_tx = if let Some(path) = options.mirror {
        let (tx, rx) = unbounded_channel();
        task::spawn(mirroring_loop(rx, path));
        Some(tx)
    } else {
        None
    };

    let scanner = if let Some(subnet) = options.arp_net {
        let scanner = Arc::new(
            SubnetScanner::new(
                subnet,
                options.arp_interface_name,
                notifier.clone(),
                options.verbose,
            )
            .expect("failed to initialize ARP scanner"),
        );

        task::spawn(arp_scan_loop(scanner.clone(), options.arp_interval));

        Some(scanner)
    } else {
        None
    };

    task::spawn(config_update_loop(
        store.clone(),
        notifier.clone(),
        scanner,
        options.domain.clone(),
        options.authoritive_nameserver,
        options.zone_file,
    ));

    task::spawn(cleanup_loop(
        store.clone(),
        notifier.clone(),
        options.purge_interval,
    ));

    println!(
        "listening on 0.0.0.0:{} (domain=*.{})",
        options.port, options.domain
    );

    http_server(store, notifier, options.port, options.domain, mirror_tx).await;
}
