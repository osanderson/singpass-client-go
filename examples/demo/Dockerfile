# Container image for the Singpass RP demo (examples/demo/cmd/server), deployed
# to Cloud Run by .github/workflows/deploy.yml.
#
# Build from the REPOSITORY ROOT, not this directory: the demo module resolves
# the library through `replace github.com/osanderson/singpass-client-go => ../..`,
# so the build context must contain both modules.
#
#   docker build -f examples/demo/Dockerfile -t singpass-demo .

# The library (via FAPIgo) needs Go 1.26.6+.
FROM golang:1.27 AS builder

WORKDIR /src

# go.work is gitignored; build each module on its own go.mod + replace.
ENV GOWORK=off CGO_ENABLED=0 GOOS=linux

# Dependency layer: cached until a go.mod / go.sum changes.
COPY go.mod go.sum ./
COPY examples/demo/go.mod examples/demo/go.sum ./examples/demo/
RUN cd examples/demo && go mod download

COPY . .
RUN cd examples/demo && go build -trimpath -ldflags="-s -w" -o /app ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app /app

# Cloud Run injects PORT; the demo listens on it (see internal/config).
# LOG_FORMAT=json makes log levels show up correctly in Cloud Logging.
ENV LOG_FORMAT=json

USER nonroot:nonroot

ENTRYPOINT ["/app"]
