# Upgrading

What to change when you upgrade across a release that breaks the API or
tightens behaviour, newest first. Patch releases (`x.y.Z`) never need code
changes. The [CHANGELOG](CHANGELOG.md) lists every change; this page shows how
to adapt to the ones that need edits.

## v0.14.0

### Protocol sessions keep one opaque record

FAPIgo v0.43.0 keeps everything a login needs between `BeginLogin` and `Complete`
(the nonce, PKCE verifier, expected issuer, redirect URI and response mode, and
from now on any `max_age`) in one opaque, versioned JSON `Record` that it owns.
A session store persists `State`, `Record` and `ExpiresAt`, and `Consume`
returns the `Record` and `ExpiresAt`. A future FAPIgo feature changes only the
record, never your store.

**`sqlstore` users:** protocol sessions move to a new table,
`<prefix>auth_sessions_v2` (`state`, `record`, `expires_at`). The old
`<prefix>auth_sessions` table isn't read any more.

1. Before deploying, create the new table: call `CreateTables` again (it only
   adds what's missing), or add it to your own migrations:

   ```sql
   CREATE TABLE singpass_auth_sessions_v2 (
       state VARCHAR(255) NOT NULL PRIMARY KEY,
       record TEXT NOT NULL,
       expires_at BIGINT NOT NULL  -- Unix nanoseconds
   );
   CREATE INDEX singpass_auth_sessions_v2_expires ON singpass_auth_sessions_v2 (expires_at);
   ```

   On MySQL, which has no `CREATE INDEX IF NOT EXISTS`, declare the index
   inline, as `CreateTables` does:

   ```sql
   CREATE TABLE singpass_auth_sessions_v2 (
       state VARCHAR(255) NOT NULL PRIMARY KEY,
       record TEXT NOT NULL,
       expires_at BIGINT NOT NULL,  -- Unix nanoseconds
       INDEX singpass_auth_sessions_v2_expires (expires_at)
   );
   ```

   If you skip this step, the first login fails with the database's "table
   doesn't exist" error naming `singpass_auth_sessions_v2`.
2. Deploy.
3. Once no instance runs the old version, drop `<prefix>auth_sessions`.

Login sessions (`<prefix>login_sessions`) are unchanged.

**Your own `Dependencies.Sessions` store:** persist `NewSession.Record` as is
(byte for byte, or as equivalent JSON) and return it as
`ConsumedSession.Record`; drop the `Nonce`, `PKCEVerifier`, `ExpectedIssuer`,
`ExpectedRedirectURI` and `ExpectedResponseMode` fields.
`storage.TestSessionStoreContract` checks the round trip. A store that returns
no record fails every callback with an error naming `NewSession.Record`.

**Either way:** a login in progress during the deploy, started on the old
version, fails at its callback, and the user starts again. Sessions last a few
minutes.

## v0.13.0

### Production: a shared DPoP key

Singpass binds each authorization code to the DPoP key the login started with,
and refuses a token request proving another key (`invalid_dpop_proof`,
verified on staging). The library used to generate the DPoP key per process,
so with more than one instance a login failed whenever its callback reached a
different instance, even with a shared `sqlstore`, and any login in flight
failed across a restart.

The product options take a `DPoPKey`, and `AssuranceProduction` now refuses
to start without one:

```
singpass: AssuranceProduction needs a DPoP key shared by every instance (DPoPKey, or NewKeyManagerWithDPoP): …
```

Generate an EC P-256 key once, keep it in your secret store with the signing
key, and pass it on every instance:

```go
dpop, err := keyfile.LoadECPrivateKey("/secrets/dpop.pem")
…
singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
    Environment: singpass.Production,
    DPoPKey:     dpop, // or an HSM/KMS crypto.Signer
    …
```

It is never published or registered, so there's nothing to change in the
portal. If you build `Dependencies.Keys` yourself, use
`singpass.NewKeyManagerWithDPoP`. Staging and development are unchanged: without
`DPoPKey` a key is still generated per process.

`singpasstest` now binds each code to the PAR's DPoP key too, so a test that
finishes a login on a different client from the one that started it fails
(with `invalid_grant`) the way it would against Singpass.

## v0.12.0

Security hardening and FAPIgo v0.40.0. No API is removed, but five behaviours
tighten:

- **`Dependencies.Debug` is refused under `AssuranceProduction`**, so
  `New` (and the product constructors with `Environment: Production`) fail
  with it set. It logs the client assertion, the authorization code and the
  PKCE verifier: turn it off in production.
- **`sqlstore` stores login sessions under a hash of the session id.** Rows
  written by an earlier version aren't found any more, so everyone signed in
  when you deploy is signed out once. The schema is unchanged.
- **`web` can limit how fast one client starts logins** (`Config.LoginRateLimit`).
  It's off unless you set it; set it for any app reachable from the internet,
  with a `Key` that finds the client's address behind your proxy. A refused
  login reaches `OnError` as `web.ErrTooManyLogins`, with `Retry-After` set.
- **Myinfo item values that look like JSON stay strings.** The parser used to
  unwrap any string beginning with `{` or `[`, including a person's own
  `value`; now it only unwraps double-encoded blocks and objects.
- **`Dependencies.AllowLoopbackHTTP` only allows literal loopback hosts**
  (FAPIgo v0.40.0): `localhost`, a name under `.localhost`, `127.0.0.0/8`
  and `::1`. A local fake issuer reached through any other name that
  resolves to loopback, such as an `/etc/hosts` alias, now fails at `New`;
  use `http://localhost:PORT` or `http://127.0.0.1:PORT` instead.

`web.New` also logs a warning when a `LoginSessions` store is set without
`SessionIdentity`, and `New` logs one when a production issuer runs without
`AssuranceProduction`.

## v0.9.0

### `Complete` takes the login's state

FAPIgo now binds each callback to the browser that started the login
(RFC 9700 §4.7), so `Complete` needs the state `BeginLogin` returned — kept
with the browser, never taken from the callback.

**Using the `web` helper:** nothing to change; it passes its state cookie.
If you implemented `web.Authenticator` yourself (e.g. a test stub), add the
parameter.

**Calling the client directly:**

```go
// Before
redirectURL, state, err := client.BeginLogin(ctx)
// … store state in a cookie, compare it with the callback's yourself …
id, err := client.Complete(ctx, r.URL.RawQuery)

// After
redirectURL, state, err := client.BeginLogin(ctx)
http.SetCookie(w, &http.Cookie{Name: "sp_state", Value: state,
    HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
// … at the callback:
var state string
if c, err := r.Cookie("sp_state"); err == nil {
    state = c.Value
}
id, err := client.Complete(ctx, r.URL.RawQuery, state)
if errors.Is(err, singpass.ErrLoginExpired) { /* "please try again" */ }
```

A missing or mismatched state matches `singpass.ErrLoginExpired`, so the
comparison you may have written yourself can go.

### Production: declare key custody

Under `AssuranceProduction` (e.g. `Environment: singpass.Production`),
construction now fails unless your keys are declared durable — they survive a
restart, as they must once Singpass has your JWKS:

```go
singpass.Dependencies{
    Sessions:   store.Sessions(),
    KeyCustody: singpass.KeyCustody{Durable: true},
}
```

A `KeyManager` or `Decrypter` you build with FAPIgo directly declares it with
`keys.DeclareCustody` instead. Leave `Dependencies.Random` unset: production
requires `crypto/rand.Reader`.

### New, optional

`singpass.ErrorCode(err)`, `ServerError(err)` and `IsTemporary(err)` read the
error Singpass sent; `Dependencies.BeginLoginRetries` retries temporary
`BeginLogin` failures.

## v0.8.0

No API removals, but startup is stricter, so a misconfiguration that used to
fail at Singpass now fails in the constructor, naming the option:

- `RedirectURI` must be an absolute `https` URL without a fragment or an IP
  address; `http://localhost` is still accepted outside production.
- `Scopes` must include `"openid"`, with each scope listed once as its own
  entry (`[]string{"openid", "name"}`, not `[]string{"openid name"}`).
- Signing and encryption key IDs must be non-empty.

Fix the option the error names; nothing else changes. New and optional: key
rotation (`AdditionalSigningKeys`, `AdditionalEncryptionKeys`), the
published-JWKS check (`CheckPublishedJWKS`, `singpass-keygen -check`) and
`web.Config.SessionIdentity`.

## v0.6.0

`Identity.SubjectAttributes()` returns a typed `SubjectAttributes` instead of
a map, and so does `ActingParty.Attributes`:

```go
// Before
attrs := id.SubjectAttributes()          // map[string]any
if attrs != nil { nric, _ := attrs["identity_number"].(string) }

// After
attrs := id.SubjectAttributes()          // singpass.SubjectAttributes
if attrs.Present() { nric := attrs.IdentityNumber }
// attrs.Raw is the map, for anything not modelled
```

## v0.5.0

`NewMyinfoBusiness` checks the `/userinfo` `sub` strictly, now that Corppass
sends the right value. If an environment still sends the client ID (the error
is `UserInfo response sub does not match the ID token's sub`), set
`MyinfoBusinessOptions.TolerateUserInfoSubjectClientID: true`.

## v0.2.0

- `singpass.OfflineClientJWKS` takes the **public** keys:
  `OfflineClientJWKS(ctx, &sig.PublicKey, sigKID, &enc.PublicKey, encKID)`.
  The JWKS is identical, so nothing needs re-registering.
- A `web.LoginSessionStore` you implemented yourself takes a context and
  returns errors: `Create(ctx, id, ttl) (string, error)`,
  `Get(ctx, sid) (*Identity, bool, error)`, `Delete(ctx, sid) error`.
- A `SessionStore` you implemented yourself should return (or wrap)
  `singpass.ErrLoginExpired` from `Consume` for an unknown, used or expired
  state.
