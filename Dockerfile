# syntax=docker/dockerfile:1.5

ARG COMMUCAT_VERSION=dev

FROM rust:1.75-bullseye AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
COPY PROTOCOL.md commucat.toml README.md ./
RUN cargo build --release -p commucat-server

FROM debian:bullseye-slim
WORKDIR /opt/commucat
RUN useradd --system --create-home commucat
COPY --from=builder /app/target/release/commucat-server /usr/local/bin/commucat-server
COPY commucat.toml ./commucat.toml
COPY migrations ./migrations
USER commucat
EXPOSE 8443
ENV COMMUCAT_CONFIG=/opt/commucat/commucat.toml
ENV COMMUCAT_VERSION=${COMMUCAT_VERSION}
ENTRYPOINT ["/usr/local/bin/commucat-server"]
