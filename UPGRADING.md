# Upgrading

What to change when you upgrade across a release that breaks the API or
tightens behaviour, newest first. Patch releases (`x.y.Z`) never need code
changes. The [CHANGELOG](CHANGELOG.md) lists every change; this page shows how
to adapt to the ones that need edits.

## v0.12.0

Security hardening. No API is removed, but four behaviours tighten:

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
