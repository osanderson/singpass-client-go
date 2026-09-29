# Container image for the Singpass RP demo (examples/demo/cmd/server), deployed
# to Cloud Run by .github/workflows/deploy.yml.
#
# Build from the REPOSITORY ROOT, not this directory: the demo module resolves
# the library through `replace github.com/osanderson/singpass-client-go => ../..`,
# so the build context must contain both modules.
#
#   docker build -f examples/demo/Dockerfile -t singpass-demo .

# The library (via FAPIgo) needs Go 1.26.6+.
# Base images are pinned by digest (Dependabot keeps the tag and digest current),
# so a re-pushed tag can't change what is built and deployed.
FROM golang:1.27@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS builder

WORKDIR /src

# go.work is gitignored; build each module on its own go.mod + replace.
ENV GOWORK=off CGO_ENABLED=0 GOOS=linux

# Dependency layer: cached until a go.mod / go.sum changes.
COPY go.mod go.sum ./
COPY examples/demo/go.mod examples/demo/go.sum ./examples/demo/
WORKDIR /src/examples/demo
RUN go mod download

WORKDIR /src
COPY . .
WORKDIR /src/examples/demo
RUN go build -trimpath -ldflags="-s -w" -o /app ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /app /app

# Cloud Run injects PORT; the demo listens on it (see internal/config).
# LOG_FORMAT=json makes log levels show up correctly in Cloud Logging.
ENV LOG_FORMAT=json

USER nonroot:nonroot

ENTRYPOINT ["/app"]
