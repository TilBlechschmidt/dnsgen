FROM alpine

RUN apk --no-cache add ca-certificates

COPY target/x86_64-unknown-linux-musl/release/server /dnsgen
COPY target/x86_64-unknown-linux-musl/release/client /dnsgen-announce

CMD /dnsgen
