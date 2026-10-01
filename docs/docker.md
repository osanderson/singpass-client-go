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
| Dashboard | `http://localhost:5156/_fake/` | `http://localhost:5157/_fake/` |

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

## Keep it local

Run the fake server only where just you, your tests or your CI can reach it:
your machine, a Compose network, a CI job. Never publish it on a network
others can reach, or put it behind a public URL. By design it:

- logs anyone in as any user, with no password
- serves its test clients' private keys
- lists every request in its dashboard

It holds no real accounts or data, but an app that trusts it would accept
those logins. Publish its ports on `localhost` only when other machines share
your network: `-p 127.0.0.1:5156:5156`.

## What your app's client must support

The fake servers speak the real protocol. Your OIDC client library must
support:

- pushed authorization requests (PAR)
- DPoP
- `private_key_jwt` client authentication
- encrypted id_tokens (ECDH-ES+A256KW, A256CBC-HS512)
- signed and encrypted `/userinfo` responses, for Myinfo

It must also accept an `http://localhost` issuer. In this library, that's
`Dependencies{AllowLoopbackHTTP: true}`. Over HTTPS (see
[Reached by a service name](#reached-by-a-service-name-over-https)), it
must trust the test CA instead.

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

## When a login fails

Open the server's dashboard, at `/_fake/` (`http://localhost:5156/_fake/` for
Singpass). It shows the issuer, the registered clients, the test users and
the last 200 requests, each with its client, status and outcome: who logged
in, or the error and how to fix it. It updates live. The same request log is
JSON at `/_fake/requests`, which a CI job can print when a test fails.

The fake server explains rejections more than Singpass does. The
`error_description` your app receives says what was wrong and, for the usual
mistakes, how to fix them:

- an unregistered client or redirect URI
- the wrong signing key or `kid`
- a `client_assertion` whose `aud` isn't the issuer
- a DPoP `htu` that isn't the server's endpoint
- a scope the client isn't registered for
- a DPoP key that changed between PAR and the token request
- a code used twice

The same explanation is in the container's log (`docker logs`), one line per
rejection.

The log also flags a request that reaches the server at another host or port
than its URL, which is what happens when you publish other ports without
changing `FAKE_SINGPASS_URL` / `FAKE_CORPPASS_URL`:

```
level=WARN msg="This request reached the server at localhost:8080, but its URL is http://localhost:5156: set the server's URL to the one clients use (…)" server=Singpass
```

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
| `FAKE_TLS_CA_DIR` | | serve HTTPS with a certificate from a test CA kept here, e.g. `/certs` |
| `FAKE_TLS_CERT`, `FAKE_TLS_KEY` | | serve HTTPS with your own certificate and key instead |

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

By default the servers use plain HTTP. This library and FAPI 2.0 only accept
plain HTTP on a loopback host, so your app must reach them at `localhost`, as
in the first two setups. To reach them by another name, use HTTPS, as in the
third.

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

### Reached by a service name, over HTTPS

When your app reaches the fake server by a name like `singpass` (an ordinary
Compose network, or a GitHub Actions job running in a container), serve
HTTPS:

- Set `FAKE_TLS_CA_DIR=/certs`. The fake server creates a test CA there on
  first start and issues itself a certificate for the host names in
  `FAKE_SINGPASS_URL` and `FAKE_CORPPASS_URL`, plus `localhost`.
- Set those URLs to the names your app uses. With TLS, `http://` URLs become
  `https://`.
- Share `/certs` with your app, and have it trust `/certs/ca.pem`. The CA
  lives in the volume, so it survives restarts.

```yaml
services:
  fake:
    image: ghcr.io/osanderson/singpass-fake-server:latest
    networks:
      default:
        aliases: [singpass, corppass]
    volumes:
      - certs:/certs
    environment:
      FAKE_TLS_CA_DIR: /certs
      FAKE_SINGPASS_URL: https://singpass:5156
      FAKE_CORPPASS_URL: https://corppass:5157

  app:
    build: .
    depends_on:
      fake:
        condition: service_healthy
    volumes:
      - certs:/certs:ro
    environment:
      SINGPASS_ISSUER: https://singpass:5156/fapi
      NODE_EXTRA_CA_CERTS: /certs/ca.pem # Node; see below for others

volumes:
  certs:
```

How your app trusts the CA depends on its language:

| Runtime | Trust `/certs/ca.pem` with |
| --- | --- |
| Node.js | `NODE_EXTRA_CA_CERTS=/certs/ca.pem` |
| Python (`requests`) | `REQUESTS_CA_BUNDLE=/certs/ca.pem` |
| Python (`ssl`, `httpx`) | `SSL_CERT_FILE=/certs/ca.pem` |
| Java | import it into a truststore with `keytool -importcert` |
| Go, with this library | an `http.Client` whose `RootCAs` holds it, as `Dependencies.HTTPClient` |

In Go, this library also refuses by default to fetch discovery and keys from
a name that resolves to a private address, which a Compose service does.
List the fake server's names in `Dependencies.AllowedPrivateHosts`:

```go
ca, err := os.ReadFile("/certs/ca.pem")
if err != nil {
	return err
}
roots := x509.NewCertPool()
roots.AppendCertsFromPEM(ca)
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.TLSClientConfig = &tls.Config{RootCAs: roots}
deps := singpass.Dependencies{
	HTTPClient:          &http.Client{Transport: transport},
	AllowedPrivateHosts: []string{"singpass", "corppass"},
}
```

The redirect URI is still where the browser goes, so the test clients'
`http://localhost` redirect URIs work if the browser runs on your machine
with your app's port published. For a browser to reach the fake server at
`https://singpass:5156`, add `127.0.0.1 singpass corppass` to your hosts
file, publish ports 5156 and 5157, and trust `ca.pem` in the browser or your
system. Headless tests with the `X-Custom-*` headers need none of that.

To use your own certificate instead, for example from
[mkcert](https://github.com/FiloSottile/mkcert), mount it and set
`FAKE_TLS_CERT` and `FAKE_TLS_KEY`. The certificate file may include
intermediates.

## Versions

Each release of this module publishes the image for `linux/amd64` and
`linux/arm64`, tagged with its version (`0.13.0`), its minor version (`0.13`)
and `latest`, with build provenance and an SBOM. Before 1.0, a minor release
may change behaviour, so pin the minor version in CI.

The latest release's image is rebuilt weekly with patched base images and Go
toolchain, and its tags move to the rebuild. Every image is tested before
it's published: this library logs in against it in each setup above. The
published `latest` is pulled and tested again daily, on amd64 and arm64. The fake server's own code
doesn't change. To keep an exact image, pin its digest
(`ghcr.io/osanderson/singpass-fake-server@sha256:…`).

The image runs as a non-root user, on a distroless base with no shell. Its
health check runs `singpass-fake-server -healthcheck`.
