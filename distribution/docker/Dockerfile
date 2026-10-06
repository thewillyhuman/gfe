# Dockerfile for `gfe-node`.
#
# The build context is the root of the repository:
#
#     docker build -f distribution/docker/Dockerfile .
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
# systemd service per `distribution/systemd/gfe-node.service`); it exists for
# CI integration tests and for environments that already standardise on
# container delivery.

ARG BINARY=builder

# Pinned Rust toolchain so the image is reproducible: bumping the Rust version
# is an explicit edit. Builds for the native target of the image's platform.
FROM rust:1.88-bookworm AS builder
WORKDIR /gfe

# What the build needs besides Rust and a C compiler: cmake builds zlib-ng,
# which Pingora links, and clang compiles the eBPF program of `netkit-kernel`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang \
 && rm -rf /var/lib/apt/lists/*

# The Cargo workspace. What of the repository reaches the build is decided by
# the ignore file next to this Dockerfile, which lets in nothing else.
COPY . .

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
LABEL org.opencontainers.image.description="General Front End — L7 TLS-terminating HTTP reverse proxy"
LABEL org.opencontainers.image.source="https://github.com/thewillyhuman/gfe"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${REVISION}"

# `ca-certificates` is the trust store the node verifies `https` backends
# against (plus `[upstream] extra_ca_file`, when set).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user. Binding 80/443 needs CAP_NET_BIND_SERVICE,
# which the operator grants (`--cap-add=NET_BIND_SERVICE`) unless the
# listeners are mapped to high ports. The kernel view needs CAP_BPF and
# CAP_NET_ADMIN, which Docker only gives to root (`--user 0 --cap-add BPF
# --cap-add NET_ADMIN`); without them the node says so and serves without it.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin --uid 65532 gfe-node \
 && mkdir -p /var/lib/gfe /etc/gfe \
 && chown gfe-node:gfe-node /var/lib/gfe

COPY --from=binary /gfe-node /usr/local/bin/gfe-node
COPY distribution/systemd/gfe-node.service /usr/lib/systemd/system/gfe-node.service

USER gfe-node
# 9101 = metrics/health ops server; 80/443 = HTTP/HTTPS listeners.
EXPOSE 9101 80 443

ENTRYPOINT ["/usr/local/bin/gfe-node"]
CMD ["--config", "/etc/gfe/gfe.toml"]
