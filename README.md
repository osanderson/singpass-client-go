# singpass-client-go — a Go relying-party library for Singpass Login, Myinfo & Myinfo Business

`github.com/osanderson/singpass-client-go` is a small Go library that lets a relying
party (RP) integrate **[Singpass Login](https://docs.developer.singpass.gov.sg/docs/products/singpass-login/key-principles)**,
**[Myinfo](https://docs.developer.singpass.gov.sg/docs/products/myinfo/introduction)**,
and **[Myinfo Business](https://docs.corppass.gov.sg/products/myinfo-business)**
(Corppass) over the **FAPI 2.0 Security Profile** without rediscovering the
Singpass/Corppass-specific details. It wraps the
[FAPIgo](https://github.com/idfoundry/fapigo) relying-party engine (**v0.32.0**),
which drives the whole protocol; this library supplies the pieces FAPIgo leaves
to the embedder and encodes the product-specific choices.

Singpass Login and Myinfo are the **same** FAPI 2.0 authorization server
(`id.singpass.gov.sg`); Myinfo Business is a **separate** authorization server run
by Corppass (`id.corppass.gov.sg`). Each product is onboarded as its **own client**
— its own `client_id` and its own signing/encryption key pair.

> **No Singpass-specific protocol shims.** FAPIgo sends the full PAR request
> (`client_id`, the plain-string `authentication_context_type` / `acr_values`
> parameters, and a DPoP proof binding the code to the DPoP key), decrypts the encrypted (JWE) `id_token` and exposes
> its validated claims, and makes the DPoP-protected `/userinfo` call. This
> library supplies only key material and small hooks — a `keys.KeyManager` (signs
> client assertions + DPoP proofs), a `keys.Decrypter` assembled from FAPIgo's own
> helpers, and a `storage.SessionStore`. There is **no JOSE code of its own**.

## Install

```sh
go get github.com/osanderson/singpass-client-go
```

Requires Go 1.26.6+ (the minimum FAPIgo requires).

## Packages

| Import | Role |
|---|---|
| `github.com/osanderson/singpass-client-go` (package `singpass`) | **Protocol core.** `Client`, `Options`, `Dependencies`, `Identity`, `DeniedError`, and the product constructors `NewLogin` / `NewMyinfo` / `NewMyinfoBusiness`. |
| `github.com/osanderson/singpass-client-go/myinfo` | **Myinfo data model.** `Response`, `Data`, `Field`, `Source`, `Kind`, `Authorisation` — the envelope-aware view `Identity.Myinfo` returns. Standard library only; `myinfo.Parse` works on any decoded `/userinfo` map. |
| `github.com/osanderson/singpass-client-go/web` | **Optional HTTP helper.** Per-app login / callback / logout / JWKS handlers, an app-session store, and cookie handling. Emits no HTML — you render via callbacks. |
| `github.com/osanderson/singpass-client-go/keyfile` | **PEM key helpers.** Generate / marshal / load EC P-256 keys. No FAPIgo dependency, so it is safe to use from key-generation tooling. |

## Quick start

The per-product constructors take just key material and a `client_id`; every
other dependency defaults to a staging-appropriate value.

```go
import (
    "context"

    singpass "github.com/osanderson/singpass-client-go"
    "github.com/osanderson/singpass-client-go/keyfile"
)

// Load the EC P-256 keys you registered with Singpass (see "Generating keys").
sigKey, _ := keyfile.LoadECPrivateKey("keys/login/sig.pem")
encKey, _ := keyfile.LoadECPrivateKey("keys/login/enc.pem")

client, err := singpass.NewLogin(context.Background(), singpass.LoginOptions{
    ClientID:      "your-client-id",
    RedirectURI:   "https://app.example.com/login/callback",
    Scopes:        []string{"openid", "name", "email"},
    SigningKey:    sigKey, // crypto.Signer — an HSM/KMS signer works too
    SigningKID:    "login-sig-1",
    EncryptionKey: encKey, // or EncryptionAgreer for an HSM/KMS-backed key (see below)
    EncryptionKID: "login-enc-1",
    // Issuer defaults to singpass.StagingSingpassIssuer; AuthContextType defaults to
    // singpass.DefaultAuthContextType. Pass a production issuer for live.
}, singpass.Dependencies{})
```

Then drive the flow:

```go
// 1. Start login: run PAR, get the redirect URL + an opaque state handle.
redirectURL, state, err := client.BeginLogin(ctx)
// … set `state` as a short-lived cookie, redirect the browser to redirectURL …

// 2. On the callback, validate + exchange the code.
id, err := client.Complete(ctx, r.URL.RawQuery)
var denied *singpass.DeniedError
if errors.As(err, &denied) {
    // user cancelled / server denied — denied.Code, denied.Description
}
// id.Subject, id.Claims, id.Scope; id.Myinfo for Myinfo / Myinfo Business.
```

Beyond `Subject` / `Scope`, `Identity` has typed accessors over the validated
id_token claims, so you needn't re-parse the raw `Claims` map or know the
Singpass/Corppass claim shapes:

```go
id.Issuer()            // "iss" — the validated FAPI issuer
id.Audience()          // "aud" as a []string (OIDC allows string or array)
id.AuthMethods()       // "amr" — how the user authenticated
id.SubjectType()       // "user" (person) vs "entity" (Corppass organisation login)
id.AssuranceContext()  // raw "acr"; id.AssuranceLevel() → the "…:loa:N" level ("2")
id.ActingParty()       // Corppass "act": the person acting for the entity (nil otherwise)
id.SubjectAttributes() // "sub_attributes" — entity name / reg number / status (Corppass)
```

`NewMyinfo` and `NewMyinfoBusiness` are the same shape; they preset
`FetchUserInfo` so `Complete` also calls the DPoP-protected `/userinfo` endpoint
and populates `Identity.Myinfo` (see "Parsing person data" below).
`NewMyinfoBusiness` additionally defaults to the Corppass issuer and enables the
Corppass `/userinfo` `sub == client_id` tolerance.

For a non-standard product or full control, use the lower-level
`singpass.New(ctx, singpass.Options{...}, singpass.Dependencies{...})` directly.

## `Options` vs `Dependencies`

`singpass.New` splits configuration in two:

- **`Options`** — protocol *behaviour*: `Issuer`, `ClientID`, `RedirectURI`,
  `Scopes`, `AuthContextType`, `AcrValues`, `FetchUserInfo`,
  `TolerateUserInfoSubjectClientID`. The product constructors fill most of this in.
- **`Dependencies`** — injected *collaborators*. Only `Keys` and `Decryption` are
  required (the product constructors build them from your key material when you
  leave them nil). **Every other field's zero value selects a staging default**,
  so `singpass.Dependencies{}` reproduces a working staging client:

  | Field | Zero-value default | Set it for production |
  |---|---|---|
  | `Sessions storage.SessionStore` | `singpass.NewMemorySessionStore(0)` (in-memory, non-durable; expires abandoned logins, caps pending ones) | a durable store (required under `AssuranceProduction`) |
  | `Assurance client.AssuranceLevel` | `AssuranceDevelopment` | `client.AssuranceProduction` |
  | `HTTPClient` / `HTTPTimeout` | `&http.Client{Timeout: 15s}` | your own client / timeout |
  | `Clock` / `Random` | `SystemClock{}` / `crypto/rand.Reader` | — |
  | `Limits` | `RecommendedLimits(HTTPTimeout)` (1h id_token, 256 KiB JOSE) | override if needed |
  | `Algorithms` | Singpass/Corppass suite | override for a non-standard product |
  | `Debug` / `Logger` | off / `slog.Default()` | leave `Debug` off in production |

Under `AssuranceProduction`, FAPIgo's client-side session-store gate rejects the
in-memory default — so a real deployment must set **both** `Assurance:
client.AssuranceProduction` **and** a `Sessions` store declaring
`storage.StoreAssurance` (`Durable` + `AtomicConsume`), or construction fails
fast rather than silently shipping a non-durable store.

## Web helper (`web`)

`web` turns one or more `*singpass.Client` into HTTP handlers, each under its own
`/{name}/*` routes, and hands rendering back to you through callbacks (it emits
no HTML):

```go
import "github.com/osanderson/singpass-client-go/web"

jwks, _ := client.PublicJWKS(ctx)
handlers := web.New(web.Config{
    Apps: []*web.App{{Name: "login", Title: "Singpass Login", Auth: client, JWKS: jwks}},
    OnAuthenticated: func(w http.ResponseWriter, r *http.Request, app *web.App, id *singpass.Identity) {
        // session cookie is already set; render or redirect
    },
    OnDenied: func(w http.ResponseWriter, r *http.Request, app *web.App, d *singpass.DeniedError) { /* … */ },
    OnError:  func(w http.ResponseWriter, r *http.Request, app *web.App, err error) { /* … */ },
})

mux := handlers.Mux() // or handlers.RegisterRoutes(yourMux)
// Add your own "/" using handlers.CurrentIdentity(r) to choose landing vs profile.
```

It registers `/{name}/login`, `/{name}/callback`, `/{name}/logout` (POST only,
cross-origin requests rejected — render it as a same-origin `<form
method="post">`), and `/{name}/jwks.json` per app, keeps a defense-in-depth state cookie, stores the
authenticated identity in a `LoginSessionStore` (set via `Config.LoginSessions`;
default `NewMemoryLoginSessionStore()`), and exposes `CookieConfig` for
names/TTLs/`Secure`/`SameSite` (set `Cookies.Secure = true` behind HTTPS). This
application login-session store is deliberately named apart from FAPIgo's
protocol session store on `Dependencies.Sessions` — they are different concepts.

## Generating keys

Each client registers two EC P-256 keys: a **signing** key (`private_key_jwt`
client assertion + DPoP) and an **encryption** key (id_token / userinfo
decryption). Both support an HSM/KMS backend so no private key need enter the
process: the signing key is any `crypto.Signer` (passed as `SigningKey`), and
the encryption key can be a `keys.ECDHAgreer` (passed as `EncryptionAgreer`,
which wins over the in-memory `EncryptionKey`) — its `AgreeSharedSecret` maps to
an HSM's `CKM_ECDH1_DERIVE` or a KMS's `DeriveSharedSecret`, while FAPIgo still
owns the Concat-KDF + key-unwrap. `keyfile` generates and loads them;
`singpass.OfflineClientJWKS` produces
the public JWKS to register during onboarding — before any `client_id` or
discovery document exists — using the same FAPIgo library code the live client's
`Client.PublicJWKS` resolves through, so the offline and online sets are
identical (`jwks.go`). The DPoP key is deliberately not published.

```go
sig, _ := keyfile.GenerateECKey()
enc, _ := keyfile.GenerateECKey()
pemBytes, _ := keyfile.MarshalECPrivateKeyPEM(sig) // write 0600
jwks, _ := singpass.OfflineClientJWKS(ctx, sig, "login-sig-1", enc, "login-enc-1")
```

The `examples/demo` module ships a ready-made `cmd/keygen` doing exactly this for
all three products.

## What Singpass/Corppass need, and where FAPIgo handles it

FAPIgo drives the generic FAPI 2.0 flow. Singpass differs from that baseline in a
few places, all handled inside FAPIgo with small hooks this library supplies:

1. **PAR request parameters (outbound) — sent by FAPIgo,** so there is no outbound
   request rewriting:
   - `client_id` — top-level PAR parameter (RFC 6749 §4.1.1 / RFC 9126).
   - **DPoP binding at PAR** — FAPIgo sends a DPoP proof in a `DPoP` header on the
     PAR request (RFC 9449 §10.1, `client.PARDPoPBindingProof`), binding the
     authorization code to the DPoP key it will use at the token endpoint.
     Singpass requires this binding up front.
   - `authentication_context_type` — required for **Login** apps
     (`APP_AUTHENTICATION_DEFAULT` for a standard login) and **rejected** on Myinfo
     / Myinfo Business requests. `NewLogin` sets it; `NewMyinfo` /
     `NewMyinfoBusiness` omit it. It rides as a plain-string FAPIgo *extension*
     (`extensions.go`), emitted as a top-level PAR parameter on the FAPI 2.0
     baseline profile.
   - `acr_values` — via `Options.AcrValues`, only if set (Singpass rejects it
     unless your client is whitelisted for it).

2. **Encrypted `id_token` (inbound) — driven by FAPIgo.** Singpass returns a JWE
   wrapping a JWS (`ECDH-ES+A256KW` + `A256CBC-HS512`). This library declares those
   algorithms and provides a `keys.Decrypter` built from FAPIgo's
   `keys.NewSingleKeyDecrypter` / `keys.NewInMemoryECDH` (`decrypter.go`).
   FAPIgo parses the compact JWE, delegates only the ECDH primitive to that
   decrypter to recover the content-encryption key, decrypts the payload, checks
   `cty=JWT`, and verifies the inner JWS itself. Declaring the algorithms also
   enables FAPIgo's **downgrade protection**: a plain (unencrypted) `id_token` is
   rejected. The validated claims land on `Identity.Claims`.

Everything else — PKCE S256, `private_key_jwt`, the token-endpoint DPoP proof,
`iss` checking (RFC 9207), and the id_token's own signature / iss / aud / nonce /
exp validation — is FAPIgo's.

### Myinfo and `/userinfo`

The id_token only proves *who* logged in; person data lives behind the
DPoP-protected `/userinfo` endpoint. When `FetchUserInfo` is set, `Complete` calls
FAPIgo's native `Client.FetchUserInfo`, which: makes the DPoP-bound `GET` (RFC
9449, with `ath`), retries once on a `401` + `DPoP-Nonce` challenge (§9), decrypts
the response JWE (`ECDH-ES+A256KW` / **`A256GCM`** — note the content encryption
differs from the id_token's `A256CBC-HS512`) through the same `keys.Decrypter`
(which serves both `IDTokenDecryption` and `UserInfoDecryption`), verifies the
inner issuer JWS (`ES256`), and checks the response `sub`. The validated result is
exposed on `Identity.Myinfo` (see below).

#### Parsing person data

Myinfo returns every data item inside an **envelope**: most fields carry a
`value`; coded fields (`sex`, `nationality`, `residentialstatus`, …) carry a
`code` + human `desc`; each also carries `source` (`1` government-verified, `2`
user-provided, `3` not applicable, `4` verified), `classification`, and
`lastupdated`; an item the source can't provide is flagged `"unavailable": true`
with no value. Addresses and phone numbers are nested objects, and some records
are arrays. Myinfo Business additionally groups data into several blocks
(`entity_info` / `person_info` / `corppass_info` / `auth_info` / `tp_auth_info`),
some of which arrive as double-encoded (stringified) JSON.

`Identity.Myinfo` (a `*myinfo.Response`, from the `myinfo` package) is a small envelope-aware accessor over that —
no map-casting, no knowledge of the envelope, and robust to Singpass adding
catalog fields (unknown fields stay reachable). It unwraps the double-encoding
for you and never panics (absent blocks/fields return zero values):

```go
if id.Myinfo != nil {                      // nil for Login (no /userinfo call)
    p := id.Myinfo.Person                  // a Data block; .Entity/.Corppass/.Auth/.TPAuth for Business
    p.Field("name").String()               // "TAN XIAO HUI"        (value, or coded desc, or "")
    p.Field("nationality").Code()          // "SG"
    p.Field("nationality").Desc()          // "SINGAPORE CITIZEN"
    p.Field("email").Available()           // false if {unavailable:true} or empty
    p.Field("name").Source()               // "1"  (raw provenance code)
    p.Field("name").SourceCode()           // myinfo.SourceGovernmentVerified (typed)
    p.Field("name").SourceCode().Authoritative()   // true — govt- or user-verified
    p.Field("name").ClassificationCode().Confidential() // true for "C"
    p.Object("regadd").Field("postal").Value()   // nested object
    p.Object("regadd").SourceCode()        // container-level provenance: grouped datasets
                                           // declare source/classification/lastupdated on the
                                           // container object, not the value leaves inside
    p.Kind("regadd")                       // myinfo.KindObject — envelope shape (Leaf/Object/List/
                                           // Scalar/Absent), for dispatching a generic walk
    p.List("vehicles")                     // []Data — repeated records
    id.Myinfo.Auth.Authorisations()        // []myinfo.Authorisation — Corppass auth_info,
                                           // the bespoke Result_Set/ESrvc_Result/Row
                                           // nesting flattened (also .TPAuth for tp_auth_info)
    id.Myinfo.Blocks()                     // recognised blocks present
    id.Myinfo.Raw()                        // full decoded response — escape hatch
}
```

`examples/demo` renders the person data from this accessor as grouped sections —
one per block, with repeated-record collections (appointments, shareholders, CPF
contribution history, …) shown as tables — and keeps the raw `/userinfo` JSON
alongside in a collapsed panel.

### Myinfo Business (Corppass)

Protocol-wise identical to Myinfo — PAR, DPoP, `private_key_jwt`, PKCE, encrypted
`id_token`, DPoP-protected `/userinfo`, same algorithms. The differences are
configuration, encoded in `NewMyinfoBusiness`:

- **Different issuer** — `id.corppass.gov.sg`, with **no `/fapi` path suffix**
  (Singpass uses `id.singpass.gov.sg/fapi`). Defaults to `singpass.StagingCorppassIssuer`.
- **Scope namespaces** — `entity.*` (organisation), `user.*` (person),
  `corppass.*` (Corppass account); each must be whitelisted on the client.
- **Multiple `/userinfo` blocks** — the response can carry `entity_info`,
  `person_info`, `corppass_info`, `auth_info`, `tp_auth_info`, each a nested object.
  `Identity.Myinfo` exposes each one as its own `Data` block (`Person`, `Entity`,
  `Corppass`, `Auth`, `TPAuth`; see `myinfo/myinfo.go`) — personal Myinfo fills only
  `Person`. Corppass also double-encodes some blocks (and nested objects) as
  stringified JSON; these are unwrapped recursively, so every block reads as real
  nested JSON.
- **`sub == client_id` tolerance** — Corppass sets the `/userinfo` `sub` to the
  `client_id` (an OIDC Core §5.3.2 deviation); `NewMyinfoBusiness` opts into
  accepting it.

See [`docs/corppass-quirks.md`](docs/corppass-quirks.md) and
[`docs/singpass-quirks.md`](docs/singpass-quirks.md) for the full details.

## Example app

[`examples/demo`](examples/demo) is a runnable web app (its own Go module) that
wires all three products through `singpass` + `web`. From that directory:

```sh
cp .env.example .env      # set SINGPASS_LOGIN_CLIENT_ID / MYINFO_CLIENT_ID / MYINFO_BIZ_CLIENT_ID
go run ./cmd/keygen       # writes keys/<app>/{sig,enc}.pem and prints each public JWKS
set -a; . ./.env; set +a
go run ./cmd/server       # http://localhost:8088
```

The demo's `go.mod` points the library at the local tree with a `replace`
directive, so changes to the library are picked up without publishing. (A local
`go.work` covering both modules works too; it is gitignored.)

### Deployment

Every push to `main` runs [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml):
it tests both modules, builds [`examples/demo/Dockerfile`](examples/demo/Dockerfile)
(from the repo root, since the demo replaces the library with `../..`), and
deploys the image to Cloud Run (service `rp-demo`, project `singpass-demo-rp`,
`asia-southeast1`) at https://rp-demo-1090410730433.asia-southeast1.run.app. GitHub authenticates keylessly through Workload Identity
Federation, which only accepts this repo on `main`.

- **Config** — [`examples/demo/deploy/cloudrun.env.yaml`](examples/demo/deploy/cloudrun.env.yaml)
  is the service's complete non-secret environment; each deploy replaces the
  service's env vars with it.
- **Keys** — each private key is a Secret Manager secret
  (`singpass-demo-<app>-<sig|enc>`) mounted at `/secrets/<app>-<sig|enc>/key.pem`.
  Only the `singpass-demo-runtime` service account can read them; the deployer
  cannot. To rotate, add a new secret version and redeploy.
- **Single instance** — pending logins and app sessions are in memory, so the
  service runs with `--max-instances=1`; a scale-to-zero or redeploy logs
  everyone out.
- **Redirect URIs** — `<APP_BASE_URL>/<app>/callback` must be registered with
  each Singpass / Corppass client alongside the localhost ones. Singpass and
  Corppass reject redirect URIs containing "singpass", "corppass" or "myinfo"
  anywhere (host included), which is why the service is `rp-demo` and the demo's
  app slugs are `login`, `mi` (Myinfo) and `mib` (Myinfo Business).

The container reads Cloud Run's `PORT` (`APP_ADDR` still wins if set), logs
JSON for Cloud Logging when `LOG_FORMAT=json` (set in the image), and shuts down
gracefully on `SIGTERM`.

## Notes & caveats

- **Staging by default.** The `Staging*` issuer constants and the `Dependencies`
  zero values target Singpass/Corppass staging. For production, pass a production
  `Issuer` and set `Assurance` + a durable `Sessions` store (see above).
- **`Debug` dumps secrets.** `Dependencies.Debug` logs outbound PAR/token/userinfo
  requests including the `client_assertion` — enable it only against staging.
- **Ephemeral DPoP key.** The DPoP proof key is generated per `KeyManager` and
  registered nowhere — sender-constraining and correctly non-persistent. It signs
  the DPoP proof at PAR, the token request and `/userinfo`, so all three match the
  token binding.
- **JOSE size cap.** FAPIgo bounds the compact JWS/JWE size it will parse. The
  default `RecommendedLimits` raises `MaxJOSECompactBytes` to 256 KiB
  (`limits.go`), since a full-scope Myinfo `/userinfo` response runs well past
  the 16 KiB baseline; fixed-shape artifacts (DPoP proofs, client assertions) are
  unaffected.

## Contributing

Commit messages and PR titles follow [Conventional Commits](https://www.conventionalcommits.org/):
`<type>(<scope>)?!?: <summary>`, with type one of `build`, `chore`, `ci`,
`docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style` or `test`, e.g.
`feat(myinfo): expose container-level source`. The rule lives in
[`scripts/check-commit-msg.sh`](scripts/check-commit-msg.sh) and is enforced
in three places:

- **Locally** — enable the bundled `commit-msg` hook once per clone:
  `git config core.hooksPath .githooks`.
- **Pull requests** — [`commit-lint.yml`](.github/workflows/commit-lint.yml)
  checks the PR title and every commit. PRs are squash-merged with the PR title
  as the commit subject.
- **Pushes to `main`** — the `commit-lint` job in
  [`deploy.yml`](.github/workflows/deploy.yml) checks the pushed commits and
  blocks the deploy if any fails.
