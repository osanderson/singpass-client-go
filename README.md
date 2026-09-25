# singpass-client-go

[![Go Reference](https://pkg.go.dev/badge/github.com/osanderson/singpass-client-go.svg)](https://pkg.go.dev/github.com/osanderson/singpass-client-go)
[![CI](https://img.shields.io/github/actions/workflow/status/osanderson/singpass-client-go/deploy.yml?branch=main&label=CI)](https://github.com/osanderson/singpass-client-go/actions/workflows/deploy.yml)
[![Release](https://img.shields.io/github/v/release/osanderson/singpass-client-go)](https://github.com/osanderson/singpass-client-go/releases)
[![License: MIT](https://img.shields.io/github/license/osanderson/singpass-client-go)](LICENSE)

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
- **Myinfo data without map-casting** — envelope-aware accessors for values,
  codes, provenance and nested records; Corppass's double-encoded blocks and
  `auth_info` handled for you.
- **HSM/KMS-ready** — the signing key is any `crypto.Signer`; decryption can use
  an external ECDH agreer, so private keys needn't enter the process.
- **Optional `net/http` helper** — login, callback, logout and JWKS routes; you
  render the pages.

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
    Apps: []*web.App{{Name: "login", Title: "Singpass", Auth: client, JWKS: jwks}},
})
mux := h.Mux() // /login/login, /login/callback, /login/logout, /login/jwks.json
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    if id, ok := h.CurrentIdentity(r); ok {
        fmt.Fprintf(w, "Signed in as %s", id.Subject)
        return
    }
    fmt.Fprint(w, `<a href="/login/login">Log in with Singpass</a>`)
})
log.Fatal(http.ListenAndServe(":8080", mux))
```

Not using the helper? `client.BeginLogin(ctx)` returns the redirect URL and a
state handle, and `client.Complete(ctx, r.URL.RawQuery)` validates the callback
and returns the `*singpass.Identity` — see the
[`Client.Complete` example](https://pkg.go.dev/github.com/osanderson/singpass-client-go#example-Client.Complete).
A cancelled or denied login comes back as a `*singpass.DeniedError`, and a stale
one (expired, reloaded or replayed callback) matches
`errors.Is(err, singpass.ErrLoginExpired)` — show a "please try again" page for
it rather than an error.

Need keys to register? `keyfile.GenerateECKey` and `singpass.OfflineClientJWKS`
produce them and the public JWKS
([example](https://pkg.go.dev/github.com/osanderson/singpass-client-go#example-OfflineClientJWKS)),
or run the demo's `go run ./cmd/keygen`.

## Myinfo person data

`NewMyinfo` and `NewMyinfoBusiness` take the same options; `Complete` then also
calls `/userinfo` and fills `Identity.Myinfo`:

```go
p := id.Myinfo.Person                    // .Entity, .Corppass, .Auth, .TPAuth for Business
p.Field("name").String()                 // "TAN XIAO HUI"
p.Field("nationality").Code()            // "SG"  (.String() gives "SINGAPORE CITIZEN")
p.Field("email").Available()             // false when Myinfo has no value
p.Field("name").SourceCode()             // myinfo.SourceGovernmentVerified
p.Object("regadd").Field("postal").String()
p.List("vehicles")                       // repeated records
id.Myinfo.Auth.Authorisations()          // Corppass auth_info, flattened
id.Myinfo.Raw()                          // the full decoded response
```

Absent blocks and fields return zero values rather than panicking. The id_token
claims have typed accessors too: `id.Issuer()`, `id.AuthMethods()`,
`id.AssuranceLevel()`, `id.SubjectType()`, `id.ActingParty()`,
`id.SubjectAttributes()`.

## Packages

| Import | Purpose |
|---|---|
| [`singpass-client-go`](https://pkg.go.dev/github.com/osanderson/singpass-client-go) | `Client`, the product constructors, `Identity`, `DeniedError` |
| [`…/myinfo`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/myinfo) | Myinfo data model; standard library only |
| [`…/web`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/web) | Optional `net/http` handlers and login sessions |
| [`…/keyfile`](https://pkg.go.dev/github.com/osanderson/singpass-client-go/keyfile) | Generate and load EC P-256 PEM keys |

## Going to production

The defaults target **staging**. For production, pass the production `Issuer`
and set `Dependencies.Assurance` to production with a durable `Sessions`
store — the in-memory default is refused under production assurance. See
[Configuration](docs/configuration.md).

## Documentation

- [API reference and examples](https://pkg.go.dev/github.com/osanderson/singpass-client-go) on pkg.go.dev
- [Configuration](docs/configuration.md) — options, dependencies, keys, staging vs production
- [How it works](docs/architecture.md) — what Singpass needs and where each piece is handled
- [Singpass quirks](docs/singpass-quirks.md) and [Corppass quirks](docs/corppass-quirks.md) — non-obvious server behaviour
- [Examples](examples) — [`minimal`](examples/minimal) (one product, ~70 lines) and [`demo`](examples/demo) (all three, [live on staging](https://rp-demo-1090410730433.asia-southeast1.run.app))

## Stability

The project is pre-1.0: minor versions may change the API, and every change is
listed in the [CHANGELOG](CHANGELOG.md). Releases follow semantic versioning.

## Contributing and security

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please
report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
