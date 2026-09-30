# Configuration

## `Options` vs `Dependencies`

`singpass.New` splits configuration in two:

- **`Options`** — protocol *behaviour*: `Issuer`, `ClientID`, `RedirectURI`,
  `Scopes`, `AuthContextType`, `AuthContextMessage`, `AcrValues`,
  `AppClaimedHTTPS`, `AppLaunchURL`, `FetchUserInfo`,
  `TolerateUserInfoSubjectClientID`. The product constructors fill most of this in.
- **`Dependencies`** — injected *collaborators*. Only `Keys` and `Decryption` are
  required (the product constructors build them from your key material when you
  leave them nil). **Every other field's zero value selects a staging default**,
  so `singpass.Dependencies{}` reproduces a working staging client:

  | Field | Zero-value default | Set it for production |
  |---|---|---|
  | `Sessions SessionStore` | `singpass.NewMemorySessionStore(0)` (in-memory, non-durable; expires abandoned logins, caps pending ones) | a durable store (required under `AssuranceProduction`) |
  | `Assurance AssuranceLevel` | `AssuranceDevelopment` | `singpass.AssuranceProduction` |
  | `HTTPClient` / `HTTPTimeout` | `&http.Client{Timeout: 15s}` | your own client / timeout |
  | `Clock` / `Random` | `SystemClock{}` / `crypto/rand.Reader` | leave `Random` unset: production requires `crypto/rand.Reader` |
  | `KeyCustody` | none declared | `KeyCustody{Durable: true}` — required under `AssuranceProduction` |
  | `BeginLoginRetries` | `0` (no retries) | up to `3`, with backoff, on temporary failures |
  | `Limits` | `RecommendedLimits(HTTPTimeout)` (1h id_token, 256 KiB JOSE) | override if needed |
  | `Algorithms` | Singpass/Corppass suite | override for a non-standard product |
  | `Debug` / `Logger` | off / `slog.Default()` | leave `Debug` off in production |

Under `AssuranceProduction` (which `Environment: singpass.Production` selects),
construction fails fast rather than silently shipping something unsafe: the
`Sessions` store must declare `singpass.StoreAssurance` (`Durable` +
`AtomicConsume`), so the in-memory default is refused; `KeyCustody` must be
`Durable`; and `Random` must be `crypto/rand.Reader`.

## Validation

The constructors check the options before contacting the issuer, and report
every problem at once, each naming the option to fix:

- `ClientID` and `RedirectURI` are required.
- `RedirectURI` must be an absolute `https` URL without a fragment, with a
  host name: the developer portal refuses IP addresses. Plain `http` is
  accepted only for `localhost`, which Singpass allows for staging apps, and
  never under `AssuranceProduction`.
- `Scopes` must include `"openid"`, and list each scope once, as its own
  entry (`[]string{"openid", "name"}`, not `[]string{"openid name"}`).
- The signing and encryption key IDs (`SigningKID`, `EncryptionKID`) must be
  set: Singpass finds your keys in the JWKS by them.

Whether a scope is approved for your client is only known to Singpass, so
unapproved scopes still fail at login.

## Staging and production

- **Staging by default.** The product options' `Environment` defaults to
  `singpass.Staging`: the staging issuers and development assurance.
  `Environment: singpass.Production` selects `ProductionSingpassIssuer` /
  `ProductionCorppassIssuer` and, unless `Dependencies.Assurance` is set,
  `AssuranceProduction`, which requires a durable `Sessions` store (see above).
  An explicit `Issuer` overrides the environment's. The full go-live list is in
  [production.md](production.md).
- **A durable `Sessions` store**: use `sqlstore` (Postgres, MySQL, SQLite), or
  implement the two-method
  `singpass.SessionStore` (`Create` / atomic `Consume`) and declare
  `singpass.StoreAssurance`. `Consume` should return (or wrap)
  `singpass.ErrLoginExpired` for an unknown, used or expired state, so callers
  can tell a stale login from a failure. Verify your implementation with
  FAPIgo's contract suite in a test:
  `storage.TestSessionStoreContract(t, func() storage.SessionStore { … })`
  (from `github.com/idfoundry/fapigo/storage`).
- **The `web` helper's login sessions** (`web.Config.LoginSessions`) are a
  separate, simpler store — `web.LoginSessionStore` (`Create` / `Get` /
  `Delete`, each taking the request context). The in-memory default is lost on
  restart and isn't shared between instances; to run more than one instance use
  `sqlstore`'s `LoginSessions()`, or implement the interface over Redis or similar.
- **`AllowLoopbackHTTP`** permits `http://localhost` issuers for a local fake
  server such as `singpasstest`'s: `localhost`, a name under `.localhost`,
  `127.0.0.0/8` or `::1`. Any other host name is refused even if it resolves
  to a loopback address (an `/etc/hosts` alias, say). It is development-only:
  `New` refuses it together with `AssuranceProduction`.
- **`Debug` dumps secrets.** `Dependencies.Debug` logs outbound PAR/token/userinfo
  requests including the `client_assertion`, the authorization code and the
  PKCE verifier — enable it only against staging. `New` refuses it under
  `AssuranceProduction`.

## Keys

Each client registers two EC P-256 keys: a **signing** key (the
`private_key_jwt` client assertion) and an **encryption** key (id_token /
userinfo decryption). Both support an HSM/KMS backend so no private key need enter the
process: the signing key is any `crypto.Signer` (passed as `SigningKey`), and
the encryption key can be a `singpass.ECDHAgreer` (passed as `EncryptionAgreer`,
which wins over the in-memory `EncryptionKey`) — its `AgreeSharedSecret` maps to
an HSM's `CKM_ECDH1_DERIVE` or a KMS's `DeriveSharedSecret`, while FAPIgo still
owns the Concat-KDF + key-unwrap. `keyfile` generates and loads them — as
PKCS#8 or SEC1 PEM, so keys made with `openssl ecparam -name prime256v1
-genkey` load as they are;
`singpass.OfflineClientJWKS` produces
the public JWKS to register during onboarding from the keys' public halves only
(so HSM/KMS-held keys work too) — before any `client_id` or
discovery document exists — using the same FAPIgo library code the live client's
`Client.PublicJWKS` resolves through, so the offline and online sets are
identical ([`keys.go`](../keys.go)).

A third key signs **DPoP** proofs. It is never published or registered, but
Singpass binds each authorization code to the DPoP key the login started with,
so every instance must use the same one: pass it as `DPoPKey` (any
`crypto.Signer`, loaded like the signing key), or build `Dependencies.Keys` with
`NewKeyManagerWithDPoP`. Left unset, a DPoP key is generated per process, which
only suits one instance in development; production assurance refuses it (see
[production.md](production.md#2-client-configuration)).

Singpass takes the JWKS as a URL it fetches (a JWKS endpoint) or pasted into
the portal (a JWKS object); see [onboarding.md](onboarding.md#3-create-a-staging-app).
After publishing the JWKS at the URL registered in the portal, check it with
`client.CheckPublishedJWKS(ctx, url)` — or, before there is a client,
`singpass.CheckPublishedJWKS(ctx, nil, url, jwks)` or `singpass-keygen -check
<url>`. It confirms every key is published under its kid with the same public
key and use, and that no private key material is exposed. Extra keys, such as
an outgoing key during a rotation, are allowed.

To rotate keys without downtime, the product options take extra keys:
`AdditionalSigningKeys` (published, never used to sign) and
`AdditionalEncryptionKeys` (decrypted with, and published unless
`DecryptOnly`). The steps are in [production.md](production.md#7-rotating-keys).

```go
// Reuses keys/login/{sig,enc}.pem, or creates them (owner-only, never overwriting).
sig, _, _ := keyfile.LoadOrGenerate("keys/login/sig.pem")
enc, _, _ := keyfile.LoadOrGenerate("keys/login/enc.pem")
jwks, _ := singpass.OfflineClientJWKS(ctx, &sig.PublicKey, "login-sig-1", &enc.PublicKey, "login-enc-1")
```

Or, from a shell: `go install github.com/osanderson/singpass-client-go/cmd/singpass-keygen@latest`,
then `singpass-keygen -dir keys/login -sig-kid login-sig-1 -enc-kid login-enc-1`.

The [`examples/demo`](../examples/demo) module's `cmd/keygen` does this for all
three products at once, reading the demo's configuration.
