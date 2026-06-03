# Multi-stage Dockerfile for `gfe-node`.
#
# Stage 1 builds the binary against a pinned Rust toolchain so the image is
# reproducible — bumping the Rust version is an explicit edit. We build for
# the host's native target by default; cross-compiles can be driven from the
# release workflow via `--platform=linux/amd64,linux/arm64`.
#
# Stage 2 ships only the runtime artifact + the systemd unit. The base image
# is a stripped Debian slim — `distroless` would be smaller but breaks
# `gfe-node --check-config` debug ergonomics and leaves the operator with no
# shell to inspect the live container.
#
# Image is *not* the recommended deploy path for production (we ship as a
# systemd service per `deploy/gfe-node.service`); it exists for CI integration
# tests and for environments that already standardise on container delivery.

FROM rust:1.87-bookworm AS builder
WORKDIR /src

# Copy the manifest first to maximise Docker layer caching: the dep build
# only re-runs when Cargo.lock or any Cargo.toml changes.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# `--locked` so the build fails if Cargo.lock is out of date; this is a
# release artifact, not a dev iteration.
RUN cargo build --release --locked --bin gfe-node


FROM debian:bookworm-slim AS runtime
ARG VERSION=unknown
ARG REVISION=unknown

LABEL org.opencontainers.image.title="gfe-node"
LABEL org.opencontainers.image.description="General Front End — L7 TLS-terminating reverse proxy"
LABEL org.opencontainers.image.source="https://github.com/thewillyhuman/gfe"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${REVISION}"

# Minimal runtime deps. `ca-certificates` covers operators who switch the
# upstream client to the system trust store; the default build verifies
# against the compiled-in webpki roots.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user. GFE only needs CAP_NET_BIND_SERVICE to bind
# 80/443; in a container the operator grants it (`--cap-add=NET_BIND_SERVICE`)
# or maps to high ports.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin --uid 65532 gfe-node \
 && mkdir -p /var/lib/gfe /etc/gfe \
 && chown gfe-node:gfe-node /var/lib/gfe

COPY --from=builder /src/target/release/gfe-node /usr/local/bin/gfe-node
COPY deploy/gfe-node.service /usr/lib/systemd/system/gfe-node.service

USER gfe-node
# 9101 = metrics/health ops server; 80/443 = HTTP/HTTPS listeners.
EXPOSE 9101 80 443

ENTRYPOINT ["/usr/local/bin/gfe-node"]
CMD ["--config", "/etc/gfe/gfe.toml"]
