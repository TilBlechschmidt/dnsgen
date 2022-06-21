use dnsgen::{parse_seconds, Announcement, AnnouncementStore};
use reqwest::StatusCode;
use std::{path::PathBuf, sync::Arc, time::Duration};
use structopt::StructOpt;
use tokio::{
    fs,
    sync::{Mutex, Notify},
    task,
    time::sleep,
};
use warp::{reply, Filter};

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
}

/// Waits for changes on the given notifier and generates a new config every time it gets notified
async fn config_update_loop(
    store: Arc<Mutex<AnnouncementStore>>,
    notifier: Arc<Notify>,
    domain: String,
    path: PathBuf,
) {
    let root_domain_len = domain.len() + 1;
    let mut zone_serial = 0;

    loop {
        let bytes = {
            let store = store.lock().await;
            let entries = store.entries();

            // For more details on zone file formatting and what the mandatory SOA entry is all about, see:
            // https://help.dyn.com/how-to-format-a-zone-file/

            let mut zone_file: String = format!(
                "@               3600 SOA {domain: >16}. zone-admin.{domain}. {zone_serial} 3600 600 604800 1800\n"
            );

            for (host, ips) in entries {
                let subdomain = &host[..host.len() - root_domain_len];
                for ip in ips {
                    zone_file += &format!("{subdomain: <16} 60 A {ip: >16}\n");
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

/// Stores announcements received via HTTP POST in the given store and sends notifications each time it does so
async fn http_server(
    store: Arc<Mutex<AnnouncementStore>>,
    notifier: Arc<Notify>,
    port: u16,
    domain: String,
) {
    let store_ref = store.clone();

    let receiver = warp::post()
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::json())
        .then(move |announcement: Announcement| {
            let store = store_ref.clone();
            let notifier = notifier.clone();
            let domain = domain.clone();

            async move {
                if !announcement.fqdn.ends_with(&domain) {
                    warp::reply::with_status(
                        "Domain name suffix not allowed",
                        StatusCode::UNAUTHORIZED,
                    )
                } else {
                    let mut store = store.lock().await;

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

    task::spawn(config_update_loop(
        store.clone(),
        notifier.clone(),
        options.domain.clone(),
        options.zone_file,
    ));

    task::spawn(cleanup_loop(
        store.clone(),
        notifier.clone(),
        options.purge_interval,
    ));

    http_server(store, notifier, options.port, options.domain).await;
}
