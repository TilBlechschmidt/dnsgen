FROM ekidd/rust-musl-builder AS builder

# We need to add the source code to the image because `rust-musl-builder`
# assumes a UID of 1000, but TravisCI has switched to 2000.
ADD --chown=rust:rust . ./

RUN cargo build --release --bin server --bin client

FROM alpine

RUN apk --no-cache add ca-certificates

COPY --from=builder /home/rust/src/target/x86_64-unknown-linux-musl/release/server /dnsgen
COPY --from=builder /home/rust/src/target/x86_64-unknown-linux-musl/release/client /dnsgen-announce

CMD /dnsgen
