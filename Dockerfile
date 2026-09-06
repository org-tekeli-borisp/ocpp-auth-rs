FROM rust:1.98 AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && touch src/lib.rs
RUN cargo fetch
COPY src ./src
RUN cargo build --release
RUN mkdir -p /out && find target/release -maxdepth 1 -type f -executable -exec cp {} /out/ \;

FROM debian:trixie-slim

COPY --from=builder /out/ /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["ocpp-auth-rs"]
