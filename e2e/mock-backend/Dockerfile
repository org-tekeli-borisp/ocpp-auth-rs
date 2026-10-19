FROM rust:1.99 AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs
RUN cargo fetch --locked
COPY src ./src
RUN cargo build --release --locked
RUN mkdir -p /out && cp target/release/mock_backend /out/

FROM debian:trixie-slim

RUN useradd --system --create-home --shell /usr/sbin/nologin ocpp
COPY --from=builder /out/ /usr/local/bin/
USER ocpp
EXPOSE 9000
CMD ["mock_backend"]
