# Configuration

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
  | `Sessions SessionStore` | `singpass.NewMemorySessionStore(0)` (in-memory, non-durable; expires abandoned logins, caps pending ones) | a durable store (required under `AssuranceProduction`) |
  | `Assurance AssuranceLevel` | `AssuranceDevelopment` | `singpass.AssuranceProduction` |
  | `HTTPClient` / `HTTPTimeout` | `&http.Client{Timeout: 15s}` | your own client / timeout |
  | `Clock` / `Random` | `SystemClock{}` / `crypto/rand.Reader` | — |
  | `Limits` | `RecommendedLimits(HTTPTimeout)` (1h id_token, 256 KiB JOSE) | override if needed |
  | `Algorithms` | Singpass/Corppass suite | override for a non-standard product |
  | `Debug` / `Logger` | off / `slog.Default()` | leave `Debug` off in production |

Under `AssuranceProduction`, FAPIgo's client-side session-store gate rejects the
in-memory default — so a real deployment must set **both** `Assurance:
singpass.AssuranceProduction` **and** a `Sessions` store declaring
`singpass.StoreAssurance` (`Durable` + `AtomicConsume`), or construction fails
fast rather than silently shipping a non-durable store.

## Staging and production

- **Staging by default.** `StagingSingpassIssuer` / `StagingCorppassIssuer` and the
  `Dependencies` zero values target Singpass/Corppass staging. For production,
  pass the production `Issuer` and set `Assurance: singpass.AssuranceProduction`
  plus a durable `Sessions` store (see above).
- **A durable `Sessions` store** implements the two-method
  `singpass.SessionStore` (`Create` / atomic `Consume`) and declares
  `singpass.StoreAssurance`. `Consume` should return (or wrap)
  `singpass.ErrLoginExpired` for an unknown, used or expired state, so callers
  can tell a stale login from a failure. Verify your implementation with
  FAPIgo's contract suite in a test:
  `storage.TestSessionStoreContract(t, func() storage.SessionStore { … })`
  (from `github.com/idfoundry/fapigo/storage`).
- **The `web` helper's login sessions** (`web.Config.LoginSessions`) are a
  separate, simpler store — `web.LoginSessionStore` (`Create` / `Get` /
  `Delete`, each taking the request context). The in-memory default is lost on
  restart and isn't shared between instances; back it with Redis or a database
  to run more than one instance.
- **`AllowLoopbackHTTP`** permits `http://localhost` issuers for a local fake
  server such as `singpasstest`'s. It is development-only: `New` refuses it
  together with `AssuranceProduction`.
- **`Debug` dumps secrets.** `Dependencies.Debug` logs outbound PAR/token/userinfo
  requests including the `client_assertion` — enable it only against staging.

## Keys

Each client registers two EC P-256 keys: a **signing** key (`private_key_jwt`
client assertion + DPoP) and an **encryption** key (id_token / userinfo
decryption). Both support an HSM/KMS backend so no private key need enter the
process: the signing key is any `crypto.Signer` (passed as `SigningKey`), and
the encryption key can be a `singpass.ECDHAgreer` (passed as `EncryptionAgreer`,
which wins over the in-memory `EncryptionKey`) — its `AgreeSharedSecret` maps to
an HSM's `CKM_ECDH1_DERIVE` or a KMS's `DeriveSharedSecret`, while FAPIgo still
owns the Concat-KDF + key-unwrap. `keyfile` generates and loads them;
`singpass.OfflineClientJWKS` produces
the public JWKS to register during onboarding from the keys' public halves only
(so HSM/KMS-held keys work too) — before any `client_id` or
discovery document exists — using the same FAPIgo library code the live client's
`Client.PublicJWKS` resolves through, so the offline and online sets are
identical ([`jwks.go`](../jwks.go)). The DPoP key is deliberately not published.

```go
sig, _ := keyfile.GenerateECKey()
enc, _ := keyfile.GenerateECKey()
pemBytes, _ := keyfile.MarshalECPrivateKeyPEM(sig) // write 0600
jwks, _ := singpass.OfflineClientJWKS(ctx, &sig.PublicKey, "login-sig-1", &enc.PublicKey, "login-enc-1")
```

The [`examples/demo`](../examples/demo) module ships a ready-made `cmd/keygen`
doing exactly this for all three products.
