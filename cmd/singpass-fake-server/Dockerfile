# Container image for singpass-fake-server: fake Singpass and Corppass FAPI 2.0
# authorization servers for testing, published to
# ghcr.io/osanderson/singpass-fake-server by .github/workflows/release-please.yml
# on each release. A community test tool, not affiliated with or endorsed by
# GovTech, Singpass or Corppass.
#
# Build from the REPOSITORY ROOT: the command is in the library's module.
#
#   docker build -f cmd/singpass-fake-server/Dockerfile -t singpass-fake-server .
#   docker run --rm -p 5156:5156 -p 5157:5157 singpass-fake-server
#
# See docs/docker.md.

# The library (via FAPIgo) needs Go 1.26.6+.
# Base images are pinned by digest (Dependabot keeps the tag and digest current),
# so a re-pushed tag can't change what is built and published. The builder runs
# on the build machine's platform and cross-compiles, so a multi-platform build
# needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS builder

WORKDIR /src

# go.work is gitignored; build the library's module on its own go.mod.
ENV GOWORK=off CGO_ENABLED=0

# Dependency layer: cached until go.mod / go.sum changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /singpass-fake-server ./cmd/singpass-fake-server

# An empty /certs for FAKE_TLS_CA_DIR, owned by the image's non-root user so a
# named volume mounted there is writable.
RUN mkdir /certs

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

LABEL org.opencontainers.image.title="singpass-fake-server" \
      org.opencontainers.image.description="Fake Singpass and Corppass FAPI 2.0 servers for testing. A community test tool, not affiliated with or endorsed by GovTech, Singpass or Corppass." \
      org.opencontainers.image.source="https://github.com/osanderson/singpass-client-go" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /singpass-fake-server /singpass-fake-server
COPY --from=builder --chown=65532:65532 /certs /certs

# Listen on every interface, so published ports reach the servers, and
# advertise the issuers at localhost, where `docker run -p 5156:5156
# -p 5157:5157` puts them. Publishing on other host ports needs
# FAKE_SINGPASS_URL / FAKE_CORPPASS_URL to match.
ENV FAKE_SINGPASS_ADDR=0.0.0.0:5156 \
    FAKE_CORPPASS_ADDR=0.0.0.0:5157 \
    FAKE_SINGPASS_URL=http://localhost:5156 \
    FAKE_CORPPASS_URL=http://localhost:5157

EXPOSE 5156 5157

# With FAKE_TLS_CA_DIR=/certs, the test CA is kept here: share the volume with
# the app, which trusts /certs/ca.pem.
VOLUME /certs

USER nonroot:nonroot

# distroless has no shell or wget: the binary checks itself, reading the same
# FAKE_* settings (over HTTPS when TLS is on).
HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=3 \
    CMD ["/singpass-fake-server", "-healthcheck"]

ENTRYPOINT ["/singpass-fake-server"]
