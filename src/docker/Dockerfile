# Dockerfile for `gfe-node`.
#
# The build context is the root of the repository:
#
#     docker build -f src/docker/Dockerfile .
#
# The image gets its binary from one of two stages, chosen with
# `--build-arg BINARY=<stage>`:
#
#   builder    (default) compiles it here, from this source tree. This is
#              what the command above and the demo do.
#   prebuilt   takes one compiled beforehand, from `prebuilt/<arch>/gfe-node`
#              in the build context, where <arch> is Docker's name for the
#              architecture (amd64, arm64). This is what the release does
#              with the binaries it publishes: they are compiled once, and
#              the arm64 image does not need a compiler run under emulation.
#
# Only the chosen stage is built. The runtime stage is the same for both and
# ships the binary + the systemd unit. Its base image is a stripped Debian
# slim: `distroless` would be smaller but breaks `gfe-node --check-config`
# debug ergonomics and leaves the operator with no shell to inspect the live
# container.
#
# Image is *not* the recommended deploy path for production (we ship as a
# systemd service per `deploy/gfe-node.service`); it exists for CI integration
# tests and for environments that already standardise on container delivery.

ARG BINARY=builder

# Pinned Rust toolchain so the image is reproducible: bumping the Rust version
# is an explicit edit. Builds for the native target of the image's platform.
FROM rust:1.88-bookworm AS builder
WORKDIR /src/rust

# clang compiles the eBPF program of `gfe-ebpf` (kernel TCP statistics).
# Without it the image still builds, with that feature unavailable.
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang \
 && rm -rf /var/lib/apt/lists/*

# The Cargo workspace and the eBPF program it compiles, where the repository
# has them.
COPY src/rust ./
COPY src/c ../c

# `--locked` so the build fails if Cargo.lock is out of date; this is a
# release artifact, not a dev iteration.
RUN cargo build --release --locked --bin gfe-node \
 && cp target/release/gfe-node /gfe-node


FROM scratch AS prebuilt
# Set by Docker to the architecture of the image being built.
ARG TARGETARCH
COPY prebuilt/${TARGETARCH}/gfe-node /gfe-node


# `COPY --from` takes no variable: this alias is what makes the stage a choice.
FROM ${BINARY} AS binary


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

COPY --from=binary /gfe-node /usr/local/bin/gfe-node
COPY deploy/gfe-node.service /usr/lib/systemd/system/gfe-node.service

USER gfe-node
# 9101 = metrics/health ops server; 80/443 = HTTP/HTTPS listeners.
EXPOSE 9101 80 443

ENTRYPOINT ["/usr/local/bin/gfe-node"]
CMD ["--config", "/etc/gfe/gfe.toml"]
