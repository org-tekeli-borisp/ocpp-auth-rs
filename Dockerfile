FROM rust:1.99 AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && touch src/lib.rs
RUN cargo fetch
COPY src ./src
RUN cargo build --release --locked --bin ocpp-auth-rs
RUN mkdir -p /out && cp target/release/ocpp-auth-rs /out/

FROM debian:trixie-slim

RUN useradd --system --create-home --shell /usr/sbin/nologin ocpp
COPY --from=builder /out/ /usr/local/bin/
USER ocpp
EXPOSE 8080
EXPOSE 8081
ENTRYPOINT ["ocpp-auth-rs"]
