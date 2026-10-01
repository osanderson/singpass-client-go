# Running the fake servers in Docker

`ghcr.io/osanderson/singpass-fake-server` is
[`singpass-fake-server`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/cmd/singpass-fake-server)
as a container image: fake Singpass and Corppass FAPI 2.0 authorization servers
for testing an app in any language, locally or in CI, without onboarding or
real accounts. It is a community test tool, not Singpass or Corppass, and is
not affiliated with or endorsed by GovTech, Singpass or Corppass.

## Quick start

```sh
docker run --rm -p 5156:5156 -p 5157:5157 ghcr.io/osanderson/singpass-fake-server
```

| | Singpass (Login, Myinfo) | Corppass (Myinfo Business) |
| --- | --- | --- |
| Issuer | `http://localhost:5156/fapi` | `http://localhost:5157` |
| Discovery | `http://localhost:5156/fapi/.well-known/openid-configuration` | `http://localhost:5157/.well-known/openid-configuration` |
| Test clients | `login-test`, `myinfo-test` | `myinfo-business-test` |
| Test client keys | `http://localhost:5156/_fake/test-client/jwks.json` | `http://localhost:5157/_fake/test-client/jwks.json` |

Configure your app with an issuer, a test client ID and the test client keys,
and log in:

- **Redirect URI:** any `http://localhost` URI, on any port and path.
- **Scopes:** any; the test clients are allowed every scope.
- **Keys:** `jwks.json` holds both private keys: the signing key
  (`test-client-sig`) and the encryption key (`test-client-enc`). The same
  keys are at `sig.pem` and `enc.pem` beside it, as PKCS#8 PEM. They are
  published, so they protect nothing: never use them anywhere else.

Logins go through a sign-in page listing the test users, with a form to log
in as any NRIC, FIN or UEN. The startup log lists the test users.

Only the Singpass server is needed for Login and Myinfo, so `-p 5157:5157`
can be dropped unless you use Myinfo Business.

## What your app's client must support

The fake servers speak the real protocol. Your OIDC client library must
support:

- pushed authorization requests (PAR)
- DPoP
- `private_key_jwt` client authentication
- encrypted id_tokens (ECDH-ES+A256KW, A256CBC-HS512)
- signed and encrypted `/userinfo` responses, for Myinfo

It must also accept an `http://localhost` issuer. In this library, that's
`Dependencies{AllowLoopbackHTTP: true}`.

## Choosing the user in headless tests

Send these headers on the authorization request (the GET of the authorization
URL your client builds). The login is then approved straight away as that
user, with no sign-in page:

| Header | Value |
| --- | --- |
| `X-Custom-NRIC` | the NRIC or FIN: a test user's, or any other for a new user |
| `X-Custom-UEN` | Corppass only, and required there: the entity |
| `X-Custom-UUID` | optional: replaces the user's Singpass UUID (`sub`, or `act.sub` on Corppass) |
| `X-Custom-Name` | optional: a new user's name |
| `X-Custom-Error` | `access_denied`: the user cancels |

Each login chooses its own user, so parallel tests don't interfere. The
headers are MockPass's, so tests written for MockPass carry over.

`FAKE_AUTO=true` instead approves every login without headers, as the first
test user.

## Configuration

Every flag of the command can be set with an environment variable, `FAKE_`
and the flag's name in capitals with underscores for hyphens:

| Variable | Default in the image | |
| --- | --- | --- |
| `FAKE_SINGPASS_ADDR` | `0.0.0.0:5156` | listen address; empty disables the Singpass server |
| `FAKE_CORPPASS_ADDR` | `0.0.0.0:5157` | listen address; empty disables the Corppass server |
| `FAKE_SINGPASS_URL` | `http://localhost:5156` | URL clients reach the Singpass server at |
| `FAKE_CORPPASS_URL` | `http://localhost:5157` | URL clients reach the Corppass server at |
| `FAKE_AUTO` | `false` | approve every login as the first test user |
| `FAKE_CLIENT_ID` | | register your own client instead of the test clients … |
| `FAKE_CLIENT_PRODUCT` | | … `login`, `myinfo` or `myinfo-business` |
| `FAKE_CLIENT_REDIRECT_URIS` | | … comma-separated |
| `FAKE_CLIENT_SCOPES` | | … comma- or space-separated |
| `FAKE_CLIENT_JWKS_URL` | | … its public JWKS |
| `FAKE_CONFIG` | | a JSON file registering any number of clients |
| `FAKE_TEST_CLIENTS` | `false` | keep the test clients alongside your own |
| `FAKE_PERSONAS` | | a JSON file of extra test users |
| `FAKE_ONLY_PERSONAS` | `false` | use only the `FAKE_PERSONAS` users |

**Different host ports.** The issuer has to be the URL your app uses. If you
publish on other host ports, change the URLs to match:

```sh
docker run --rm -p 8080:5156 -e FAKE_SINGPASS_URL=http://localhost:8080 -e FAKE_CORPPASS_ADDR= \
  ghcr.io/osanderson/singpass-fake-server
```

**Your own client and keys.** The fake server fetches your app's public
JWKS. From inside the container, `localhost` is the container itself, so an
app running on your machine is at `host.docker.internal`. On Linux, add
`--add-host=host.docker.internal:host-gateway`.

```sh
docker run --rm -p 5156:5156 -e FAKE_CORPPASS_ADDR= \
  -e FAKE_CLIENT_ID=my-app -e FAKE_CLIENT_PRODUCT=myinfo \
  -e FAKE_CLIENT_REDIRECT_URIS=http://localhost:3000/callback -e FAKE_CLIENT_SCOPES=uinfin,name \
  -e FAKE_CLIENT_JWKS_URL=http://host.docker.internal:3000/jwks.json \
  ghcr.io/osanderson/singpass-fake-server
```

The JWKS is retried until your app serves it, so the two can start in any
order. For several clients, or a JWKS file, mount a configuration file and set
`FAKE_CONFIG`:

```sh
docker run --rm -p 5156:5156 -p 5157:5157 \
  -v ./clients.json:/config/clients.json:ro -e FAKE_CONFIG=/config/clients.json \
  ghcr.io/osanderson/singpass-fake-server
```

The command's documentation describes the file. `FAKE_PERSONAS` adds test
users from a mounted file in the same way.

## Where your app runs

The servers use plain HTTP, which this library and FAPI 2.0 only accept on a
loopback host. So your app must reach them at `localhost`.

### On your machine, or a GitHub Actions job on the runner

Publish the ports, as in the quick start. In GitHub Actions, run the image as
a service container. The image has a health check, so the job waits for it
to be ready:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      singpass:
        image: ghcr.io/osanderson/singpass-fake-server:latest # pin a version, e.g. :0.13
        ports:
          - 5156:5156
          - 5157:5157
        env:
          FAKE_AUTO: "true" # optional: or choose users with the X-Custom-* headers
    steps:
      - uses: actions/checkout@v5
      - run: make test # issuer http://localhost:5156/fapi
```

This doesn't work for a job that runs in a container (`jobs.<id>.container`).
There, the service is reached by its name, not `localhost`.

### In Docker Compose

Run your app in the fake server's network namespace with
`network_mode: "service:singpass"`. `localhost` is then the same for your
app, the fake server and, through the published ports, your browser. Publish
your app's ports on the fake server's service, since the app now shares its
network:

```yaml
services:
  singpass:
    image: ghcr.io/osanderson/singpass-fake-server:latest
    ports:
      - "5156:5156" # Singpass
      - "5157:5157" # Corppass
      - "3000:3000" # your app
    environment:
      FAKE_CLIENT_ID: my-app
      FAKE_CLIENT_PRODUCT: myinfo
      FAKE_CLIENT_REDIRECT_URIS: http://localhost:3000/callback
      FAKE_CLIENT_SCOPES: uinfin,name
      FAKE_CLIENT_JWKS_URL: http://localhost:3000/jwks.json

  app:
    build: .
    network_mode: "service:singpass"
    depends_on:
      singpass:
        condition: service_healthy
    environment:
      SINGPASS_ISSUER: http://localhost:5156/fapi
```

Your app still reaches other services (a database, say) by their names.

### Reached by a service name

An app that reaches the fake server by its service name (`http://singpass:5156`)
isn't supported yet: that needs HTTPS. Use one of the setups above.

## Versions

Each release of this module publishes the image for `linux/amd64` and
`linux/arm64`, tagged with its version (`0.13.0`), its minor version (`0.13`)
and `latest`, with build provenance and an SBOM. Before 1.0, a minor release
may change behaviour, so pin the minor version in CI.

The image runs as a non-root user, on a distroless base with no shell. Its
health check runs `singpass-fake-server -healthcheck`.
