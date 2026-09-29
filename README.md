# singpass-client-go

[![Go Reference](https://pkg.go.dev/badge/github.com/osanderson/singpass-client-go.svg)](https://pkg.go.dev/github.com/osanderson/singpass-client-go)
[![CI](https://img.shields.io/github/actions/workflow/status/osanderson/singpass-client-go/deploy.yml?branch=main&label=CI)](https://github.com/osanderson/singpass-client-go/actions/workflows/deploy.yml)
[![Release](https://img.shields.io/github/v/release/osanderson/singpass-client-go)](https://github.com/osanderson/singpass-client-go/releases)
[![License: MIT](https://img.shields.io/github/license/osanderson/singpass-client-go)](LICENSE)
[![Quality Gate](https://sonarcloud.io/api/project_badges/quality_gate?project=osanderson_singpass-client-go)](https://sonarcloud.io/summary/new_code?id=osanderson_singpass-client-go)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=osanderson_singpass-client-go&metric=coverage)](https://sonarcloud.io/summary/new_code?id=osanderson_singpass-client-go)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=osanderson_singpass-client-go&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=osanderson_singpass-client-go)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=osanderson_singpass-client-go&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=osanderson_singpass-client-go)

A Go library for integrating **[Singpass Login](https://docs.developer.singpass.gov.sg/docs/products/singpass-login/key-principles)**,
**[Myinfo](https://docs.developer.singpass.gov.sg/docs/products/myinfo/introduction)** and
**[Myinfo Business](https://docs.corppass.gov.sg/products/myinfo-business)** (Corppass)
over the FAPI 2.0 Security Profile — PAR, DPoP, `private_key_jwt`, PKCE,
encrypted id_tokens and `/userinfo` — without rediscovering the
Singpass/Corppass-specific details. The protocol is driven by
[FAPIgo](https://github.com/idfoundry/fapigo); this library supplies the
Singpass pieces.

> **Unofficial.** A community project, not affiliated with or endorsed by
> GovTech, Singpass or Corppass.

- **One constructor per product** — `NewLogin`, `NewMyinfo`, `NewMyinfoBusiness`
  — with working staging defaults.
- **Typed Myinfo data** — `PersonProfile()` and `EntityProfile()` name the
  common items, with dates, numbers, addresses and phone numbers parsed;
  provenance kept on every item; Corppass's double-encoded blocks and
  `auth_info` handled for you.
- **HSM/KMS-ready** — the signing key is any `crypto.Signer`; decryption can use
  an external ECDH agreer, so private keys needn't enter the process.
- **Optional `net/http` helper** — login, callback, logout and JWKS routes; you
  render the pages.
- **Test without onboarding** — `singpasstest` runs a fake Singpass/Corppass
  server in-process for integration tests, `singpass-fake-server` runs it
  standalone for apps in any language, and the demo runs against it with one
  environment variable.
- **Production pieces included** — `Environment: singpass.Production`, durable
  session stores (`sqlstore`), key rotation without downtime, a published-JWKS
  check, retries for temporary Singpass errors, browser security headers
  (`web.SecureHeaders`) and a key generator (`singpass-keygen`).

**Try it now**, no Singpass account or onboarding needed:

```sh
git clone https://github.com/osanderson/singpass-client-go
cd singpass-client-go/examples/demo
DEMO_MOCK=1 go run ./cmd/server   # open http://localhost:8088
```

## Install

```sh
go get github.com/osanderson/singpass-client-go
```

Requires Go 1.26.6+ (FAPIgo's minimum). The package name is `singpass`.

## Quick start

A complete Singpass Login app — also in [`examples/minimal`](examples/minimal):

```go
sigKey, _ := keyfile.LoadECPrivateKey("keys/sig.pem") // keys you registered with Singpass
encKey, _ := keyfile.LoadECPrivateKey("keys/enc.pem")

client, err := singpass.NewLogin(ctx, singpass.LoginOptions{
    ClientID:      "your-client-id",
    RedirectURI:   "https://app.example.com/login/callback",
    Scopes:        []string{"openid", "name"},
    SigningKey:    sigKey,
    SigningKID:    "login-sig-1",
    EncryptionKey: encKey,
    EncryptionKID: "login-enc-1",
}, singpass.Dependencies{}) // zero value = staging defaults
if err != nil {
    log.Fatal(err)
}
jwks, _ := client.PublicJWKS(ctx)

h := web.New(web.Config{
    Apps:            []*web.App{{Name: "login", Title: "Singpass", Auth: client, JWKS: jwks}},
    SessionIdentity: web.MinimalIdentity, // keep personal data out of the login session
    LoginRateLimit:  &web.LoginRateLimit{}, // 10 logins at once per IP, then 10 a minute
    // Behind HTTPS, also set Cookies: web.DefaultCookieConfig(true) (Secure, __Host- names).
})
mux := h.Mux() // /login/login, /login/callback, /login/logout, /login/jwks.json
mux.Handle("/", web.NoStore(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if id, ok := h.CurrentIdentity(r); ok { // never cache pages showing the identity
        fmt.Fprintf(w, "Signed in as %s", id.Subject)
        return
    }
    fmt.Fprint(w, `<a href="/login/login">Log in with Singpass</a>`)
})))
log.Fatal(http.ListenAndServe(":8080", web.SecureHeaders(mux))) // CSP, anti-framing, HSTS, …
```

Not using the helper? `client.BeginLogin(ctx)` returns the redirect URL and the
login's state — keep it in a cookie — and `client.Complete(ctx, r.URL.RawQuery, state)`
validates the callback against that browser's state and returns the
`*singpass.Identity` — see the
[`Client.Complete` example](https://pkg.go.dev/github.com/osanderson/singpass-client-go#example-Client.Complete).
A cancelled or denied login comes back as a `*singpass.DeniedError`, and a stale
one (expired, reloaded or replayed callback) matches
`errors.Is(err, singpass.ErrLoginExpired)` — show a "please try again" page for
it rather than an error. `singpass.ErrorCode(err)` gives the error code Singpass
sent, and `singpass.IsTemporary(err)` says whether trying again may help
(`Dependencies.BeginLoginRetries` retries `BeginLogin` for you).

For Singpass Login, `LoginOptions.AuthContextMessage` — or
`client.BeginLoginWith(ctx, singpass.LoginContext{Message: …})` for one login —
tells the user what they're authenticating for, and `AppClaimedHTTPS` /
`AppLaunchURL` cover logins started from a mobile app.

New to Singpass? The [onboarding guide](docs/onboarding.md) walks through the
developer portal and maps each setting to these options.

Need keys to register? The `singpass-keygen` command creates both keys (or
reuses existing ones — it never overwrites) and prints the public JWKS:

```sh
go install github.com/osanderson/singpass-client-go/cmd/singpass-keygen@latest
singpass-keygen -dir keys/login -sig-kid login-sig-1 -enc-kid login-enc-1 > login.jwks.json
```

To publish several keys, as in a key rotation, list each one with
`-sig PATH=KID` / `-enc PATH=KID` instead of `-dir`.
In code, `keyfile.LoadOrGenerate` and `singpass.OfflineClientJWKS` do the same
([example](https://pkg.go.dev/github.com/osanderson/singpass-client-go#example-OfflineClientJWKS)).

Once your JWKS is published at the URL you registered, check it serves these
keys. A JWKS URL with stale or other keys otherwise shows up at login only as
`invalid_client`:

```sh
singpass-keygen -dir keys/login -sig-kid login-sig-1 -enc-kid login-enc-1 -check https://app.example.com/login/jwks.json
```

From a running app, `client.CheckPublishedJWKS(ctx, url)` does the same, e.g.
as a readiness check. The constructors also check your options up front:
a missing `openid` scope, a malformed, non-https or IP-address redirect URI and
an empty key ID fail at startup, with an error naming the option, rather than at
Singpass.

## Test accounts

Singpass and Corppass publish staging test personas with Myinfo data:
[Myinfo test personas](https://docs.developer.singpass.gov.sg/docs/testing/myinfo-test-personas)
and [Myinfo Business test personas](https://docs.corppass.gov.sg/testing/myinfo-business-test-personas).
Log in with the persona's UINFIN and the password given on those pages. The
Myinfo personas also sign in to staging Singpass Login apps, but Singpass
doesn't support that use. Persona data changes without notice, so don't
hard-code it. No staging client yet? Try the demo with `DEMO_MOCK=1`, or run
your own app against [`singpass-fake-server`](#testing-your-integration).

## Myinfo person data

`NewMyinfo` and `NewMyinfoBusiness` take options shaped like `NewLogin`'s.
Myinfo scopes are per data item; `myinfo.Scopes` expands items to the scopes
Singpass's data catalogue lists for them (`vehicles` alone is 37):
`Scopes: myinfo.Scopes("openid", myinfo.ItemName, myinfo.ItemVehicles)`. For
Myinfo Business, use the block-prefixed items:
`myinfo.Scopes("openid", myinfo.EntityBasicProfile, myinfo.EntityAppointments, myinfo.UserName)`.
`Complete` then also calls `/userinfo` and fills `Identity.Myinfo`. The typed
profiles name the common items, so there are no keys to look up:

```go
p := id.Myinfo.PersonProfile()
p.Name.String()                          // "TAN XIAO HUI"
p.Nationality.Code()                     // "SG"  (.String() gives "SINGAPORE CITIZEN")
dob, ok := p.DOB.Date()                  // time.Time
p.RegAdd.Lines()                         // ["102 BEDOK NORTH AVENUE 4", "#09-128", "SINGAPORE 460102"]
p.MobileNo.E164()                        // "+6597399245"
p.CPFBalances.OA.Float()                 // 1581.48, true
p.NOABasic.Amount.Float()                // latest assessable income; .NOA for the breakdown
p.Vehicles[0].COEExpiryDate.Date()       // also HDBOwnership, DrivingLicence, NOAHistory, CPFContributions, …
p.PartialUINFIN.String()                 // "****381D": masked NRIC, for display without the full number
p.Email.Available()                      // false when Myinfo has no value
p.Name.SourceCode()                      // myinfo.SourceGovernmentVerified

e := id.Myinfo.EntityProfile()           // Myinfo Business
e.Name.String(); e.RegistrationNumber.String(); e.UENStatus.Code(); e.Address.String()
e.Appointments; e.Shareholders           // person or entity party, flattened
e.Financials[0].Company.Revenue.Float()  // also Capitals, Licences, Grants, History, …
id.Myinfo.CorppassProfile().Email        // the acting user's Corppass account
id.Myinfo.Auth.Authorisations()          // Corppass auth_info, flattened
```

Every item is a `myinfo.Field`, keeping its value, code, provenance and
classification. For items the profiles don't model, read the blocks by key:

```go
id.Myinfo.Person.Object("drivinglicence") // .Entity, .Corppass, .Auth, .TPAuth for Business
id.Myinfo.Person.List("vehicles")        // repeated records
id.Myinfo.Person.Leaves()                // every item with its key path, e.g. for a table or a DB row
p.RegAdd.Data.EffectiveSource()          // provenance, incl. source declared on the container
myinfo.Label("hdbownership")             // "HDB ownership" — display labels for keys
id.Myinfo.Raw()                          // the full decoded response
```

Absent blocks and fields return zero values rather than panicking. The id_token
claims have typed accessors too: `id.Issuer()`, `id.AuthMethods()`,
`id.AssuranceLevel()`, `id.SubjectType()`, and `id.SubjectAttributes()` with
named fields (`IdentityNumber`, `AccountType`, `Name`, … for a person;
`EntityName`, `EntityRegNumber`, … for a Corppass entity). For Corppass,
`id.ActingParty()` is the person acting for the entity, with the same typed
`Attributes`.

## Packages

| Import | Purpose |
|---|---|
| [`singpass-client-go`](https://pkg.go.dev/github.com/osanderson/singpass-client-go) | `Client`, the product constructors, `Identity`, `DeniedError` |
| [`…/myinfo`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/myinfo) | Myinfo data model; standard library only |
| [`…/web`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/web) | Optional `net/http` handlers and login sessions |
| [`…/keyfile`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/keyfile) | Generate and load EC P-256 PEM keys |
| [`…/singpasstest`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/singpasstest) | Fake Singpass / Corppass server for tests and demos |
| [`…/sqlstore`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/sqlstore) | Durable session stores on Postgres, MySQL or SQLite (`database/sql`, no dependencies) |
| [`…/cmd/singpass-keygen`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/cmd/singpass-keygen) | Command: create a client's keys and print the JWKS to register |
| [`…/cmd/singpass-fake-server`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/cmd/singpass-fake-server) | Command: run the fake Singpass and Corppass servers standalone, for apps in any language |

## Testing your integration

`singpasstest` runs a fake Singpass or Corppass authorization server in-process,
built on FAPIgo's real server engine: PAR, DPoP, `private_key_jwt`, PKCE,
encrypted id_tokens and signed, encrypted `/userinfo`, plus the
Singpass/Corppass quirks. Register your client with it, point the client at
`srv.Issuer()` with `Dependencies{AllowLoopbackHTTP: true}`, and drive a full
login in a test. Its built-in test users carry Myinfo data across the typed
datasets (CPF, income tax, HDB, vehicles, driving licence, children, a
foreigner's pass), and its sign-in page — or `singpasstest.UserPersona` /
`EntityPersona` in code — logs in as any NRIC, FIN or UEN you choose. See the
[example](https://pkg.go.dev/github.com/osanderson/singpass-client-go/singpasstest#example-package).

To use the fake servers from an app in any language, or by hand in a
browser, run them standalone and register your clients in a JSON file:

```sh
go install github.com/osanderson/singpass-client-go/cmd/singpass-fake-server@latest
singpass-fake-server -config clients.json   # Singpass at http://127.0.0.1:5156/fapi, Corppass at http://127.0.0.1:5157
```

See the [command's documentation](https://pkg.go.dev/github.com/osanderson/singpass-client-go/cmd/singpass-fake-server)
for the file format.

**Your own test users.** Add them from a JSON file — to the standalone server
with `-personas users.json`, to the demo's mock mode with
`DEMO_MOCK_PERSONAS=users.json`, or to a test with
[`singpasstest.LoadPersonas`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/singpasstest#LoadPersonas).
Each user is an NRIC (or, for Corppass, a UEN and the acting person's NRIC)
with optional `/userinfo` data in Myinfo's shape, so a real staging response —
like the demo's "Raw /userinfo response" — can be pasted in as-is:

```json
[{"nric": "S1234567D", "userinfo": {"person_info": {"name": {"value": "TAN AH KOW"}}}}]
```

## Going to production

The defaults target **staging**. For production, set
`Environment: singpass.Production` in the product options: it selects the
production issuer and production assurance, under which the in-memory session
store is refused, so supply a durable `Dependencies.Sessions` — `sqlstore`
provides one (and the `web` helper's login sessions) on Postgres, MySQL or
SQLite — and declare durable keys with
`Dependencies.KeyCustody: singpass.KeyCustody{Durable: true}`. Work through the [go-live checklist](docs/production.md), which also
covers [rotating keys](docs/production.md#7-rotating-keys) without downtime.

## Documentation

- [API reference and examples](https://pkg.go.dev/github.com/osanderson/singpass-client-go) on pkg.go.dev
- [Onboarding](docs/onboarding.md) — from portal setup to a working staging login, step by step
- [Troubleshooting](docs/troubleshooting.md) — error codes and symptoms, with their causes and fixes
- [Configuration](docs/configuration.md) — options, dependencies, keys, staging vs production
- [Going to production](docs/production.md) — the go-live checklist
- [Upgrading](UPGRADING.md) — what to change for each breaking release
- [How it works](docs/architecture.md) — what Singpass needs and where each piece is handled
- [Singpass quirks](docs/singpass-quirks.md) and [Corppass quirks](docs/corppass-quirks.md) — non-obvious server behaviour
- [Examples](examples) — [`minimal`](examples/minimal) (one product, ~75 lines) and [`demo`](examples/demo) (all three, [live on staging](https://rp-demo-1090410730433.asia-southeast1.run.app))

## Stability

The project is pre-1.0 and follows semantic versioning:

- **Patch releases** (`0.9.x`) never break the API.
- **Minor releases** (`0.x.0`) may. Each breaking change is marked in the
  [CHANGELOG](CHANGELOG.md) and explained, with before/after code, in
  [UPGRADING.md](UPGRADING.md).
- **1.0** will follow once the API has held through real integrations of all
  three products and a release cycle without breaking changes; from then on,
  breaking changes wait for a major version.

Much of the churn so far has come from tracking [FAPIgo](https://github.com/idfoundry/fapigo),
which is also pre-1.0; this library absorbs its changes where it can, so most
FAPIgo upgrades need nothing from you.

## Contributing and security

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please
report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
