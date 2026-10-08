FROM rust:1.92-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY schemas ./schemas
COPY schema.sql ./
RUN cargo build --locked --release --bin orchid-catalog

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/orchid-catalog /usr/local/bin/orchid-catalog
RUN useradd --system --uid 10001 catalog && mkdir /data && chown catalog:catalog /data
USER catalog
WORKDIR /data
ENV ORCHID_CATALOG_LISTEN=0.0.0.0:8182
EXPOSE 8182
ENTRYPOINT ["orchid-catalog"]
