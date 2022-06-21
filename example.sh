# 1. Start the DNS server — in this case on a separate port because 53 is probably in use
coredns -dns.port=1053 &

# 2. Run the HTTP server with a domain and zone file location
cargo run --bin server -- --verbose ppidev.net zones/db.ppidev.net

# 3. Announce ourselves, subnet filter might not be correct for your interface/network
cargo run --bin client -- --subnet 10.0.0.0/16 --server http://localhost:3030 cool-cluster.ppidev.net

# 4. Query the DNS server
dig @localhost -p 1053 a cool-cluster.ppidev.net

# 5. PROFIT!
