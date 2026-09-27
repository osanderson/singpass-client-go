# Going to production

A checklist for taking a singpass-client-go integration from staging to
production. The library defaults to staging; production needs a few explicit
choices, and the library refuses the unsafe ones.

## 1. Onboarding

- [ ] **A production client per product.** Singpass Login, Myinfo and Corppass
      Myinfo Business are each onboarded separately, with their own `client_id`.
      Staging client IDs don't work in production.
- [ ] **New keys for production.** Generate separate signing and encryption keys
      for each production client, rather than reusing staging keys. Prefer
      HSM/KMS-held keys: pass a `crypto.Signer` as `SigningKey`, and an
      `ECDHAgreer` as `EncryptionAgreer`. Register the public JWKS:
      `OfflineClientJWKS` needs only the public keys.
- [ ] **The JWKS URL serves those keys.** Once deployed, check the URL
      registered in the portal with `client.CheckPublishedJWKS(ctx, url)`
      (e.g. as a readiness check) or
      `singpass-keygen -dir … -sig-kid … -enc-kid … -check <url>`. A JWKS URL
      serving stale or other keys shows up at login only as `invalid_client`.
      Run the check again after every key rotation.
- [ ] **Production redirect URIs**, over `https`, registered exactly as the app
      sends them. The constructors refuse a plain-`http` redirect URI under
      production assurance. They must not contain "singpass", "corppass" or "myinfo" (see
      [singpass-quirks.md](singpass-quirks.md)).
- [ ] **Scopes whitelisted.** Request only scopes the production client is
      approved for; anything else is rejected.

## 2. Client configuration

```go
client, err := singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
    Environment: singpass.Production, // production issuer + AssuranceProduction
    ClientID:    os.Getenv("MYINFO_CLIENT_ID"),
    RedirectURI: "https://app.example.com/mi/callback",
    Scopes:      []string{"openid", "name", "uinfin"},
    SigningKey:  signer, SigningKID: "myinfo-sig-2026",
    EncryptionAgreer: agreer, // HSM/KMS ECDH; or EncryptionKey + EncryptionKID
}, singpass.Dependencies{
    Sessions: durableStore, // required under AssuranceProduction; see §3
})
```

- [ ] **`Environment: singpass.Production`.** This selects the production issuer
      (`https://id.singpass.gov.sg/fapi`, or `https://id.corppass.gov.sg` for
      Myinfo Business) and, unless you set `Dependencies.Assurance` yourself,
      `AssuranceProduction`.
- [ ] **`Dependencies.Debug` off.** It logs the client assertion.
- [ ] **`Dependencies.AllowLoopbackHTTP` off.** It's refused under
      `AssuranceProduction` anyway.
- [ ] **`HTTPClient` / `HTTPTimeout`** suit your egress: proxy, timeouts, and
      access to `id.singpass.gov.sg` / `id.corppass.gov.sg`.
- [ ] **Myinfo Business: the `/userinfo` `sub` check.** Corppass has fixed its
      former `sub` = `client_id` deviation — confirmed on staging only. If a
      production login fails with `UserInfo response sub does not match the ID
      token's sub`, set `MyinfoBusinessOptions.TolerateUserInfoSubjectClientID`
      (see [corppass-quirks.md](corppass-quirks.md)).

## 3. Durable session stores

The [`sqlstore`](../sqlstore) package provides both stores below on Postgres,
MySQL or SQLite, using `database/sql` with your driver:

```go
store := sqlstore.New(db, sqlstore.Config{Dialect: sqlstore.Postgres})
if err := store.CreateTables(ctx); err != nil { /* … */ }
deps := singpass.Dependencies{Sessions: store.Sessions()}
h := web.New(web.Config{LoginSessions: store.LoginSessions() /* … */})
// Periodically: store.DeleteExpired(ctx)
```

To use Redis or another backend, implement the interfaces below.

Under `AssuranceProduction` the in-memory session store is refused at
construction:

```
singpass: construct client: client: dependencies: sessions must implement storage.StoreAssurance under AssuranceProduction
```

- [ ] **Protocol sessions (`Dependencies.Sessions`, a `singpass.SessionStore`).**
      These hold the state, nonce and PKCE verifier between `BeginLogin` and
      `Complete`, for a few minutes. The store must:
      - be **shared by every instance**, since the callback can reach a
        different instance from the one that started the login;
      - **consume atomically**, exactly once per state;
      - declare `singpass.StoreAssurance`.

      `Consume` should return (or wrap) `singpass.ErrLoginExpired` for an
      unknown, already-used or expired state. Verify it with
      `storage.TestSessionStoreContract` from `github.com/idfoundry/fapigo/storage`.
- [ ] **Login sessions (`web.Config.LoginSessions`, a `web.LoginSessionStore`),**
      if you use the `web` helper. These hold the signed-in identity behind the
      session cookie. The in-memory default is lost on restart and isn't
      shared, so it's unsuitable for more than one instance.

## 4. Web and cookies

- [ ] **Serve over HTTPS** and set `Cookies: web.DefaultCookieConfig(true)` (or
      `Cookies.Secure = true`). Secure cookies get `__Host-` names, which
      browsers only accept with `Secure`, `Path=/` and no `Domain`.
- [ ] **Wrap the app in `web.SecureHeaders`** — a strict Content-Security-Policy
      for script-free pages, anti-framing, `nosniff`, `Referrer-Policy:
      no-referrer` (callback URLs carry the code and state) and HSTS over HTTPS.
      Use `web.SecureHeadersWithPolicy` if your pages need scripts or other
      origins.
- [ ] **Wrap every page that shows the identity in `web.NoStore`**, so personal
      data can't be reopened from the browser cache after logout. The helper's
      own login, callback and logout responses are already no-store.
- [ ] **Keep `SameSite=Lax`** (the default). The callback is a top-level
      cross-site navigation from Singpass, which `Strict` would break.
- [ ] **Render logout as a same-origin `<form method="post">`.** `web` rejects
      GET and cross-origin logout requests.

## 5. Error handling

| Error | Meaning | Suggested response |
|---|---|---|
| `*singpass.DeniedError` | User cancelled, or Singpass denied the request | Friendly "login cancelled" page |
| `singpass.ErrLoginExpired` (incl. `web.ErrStateMismatch`) | Stale, reloaded or replayed callback, or a restart mid-login | "Please try again" with a login link |
| `singpass.ErrTooManyPendingLogins` | In-memory store at its cap (development only) | 503 |
| anything else | Protocol, network or configuration failure | Log it; generic error page |

## 6. Personal data and operations

- [ ] **Treat Myinfo data as personal data.** Most fields are classified
      confidential (`Field.ClassificationCode().Confidential()`). Keep only what
      you need, and handle it under your data-protection obligations (e.g. the
      PDPA) and your Singpass/Corppass terms.
- [ ] **Keep personal data out of logs.** Don't log `Identity.Claims`,
      `Identity.Myinfo.Raw()` or tokens.
- [ ] **Show only what the user needs.** The demo renders every field and the
      raw `/userinfo` JSON to illustrate the library — don't copy that into a
      production app.
- [ ] **Keep clocks in sync (NTP).** Token and DPoP validation compare
      timestamps, allowing only small skew.
- [ ] **Monitor login outcomes:** denied, expired and failed rates, and errors
      calling `id.singpass.gov.sg`.
- [ ] **Stay current.** Watch the repository's releases, and read the
      [CHANGELOG](../CHANGELOG.md) before upgrading: pre-1.0 minor versions may
      change the API. Security fixes are announced as GitHub security
      advisories.

## 7. Rotating keys

Singpass and Corppass fetch your JWKS and cache it for up to an hour, so a
rotation publishes the new key first and keeps the old one usable until every
cache has expired. The steps below follow their documented procedures
([Singpass](https://docs.developer.singpass.gov.sg/docs/technical-specifications/technical-concepts/json-web-key-sets-jwks),
[Corppass](https://docs.corppass.gov.sg/technical-specifications/technical-concepts/client-jwks)).
Rehearse on staging first, and run `client.CheckPublishedJWKS` (or
`singpass-keygen -check`) after each deploy.

**Signing key** (S1 → S2): publish S2, wait, then sign with it.

1. Deploy with S2 published but not used to sign:

   ```go
   SigningKey: s1, SigningKID: "sig-1",
   AdditionalSigningKeys: []singpass.PublishedKey{{Key: &s2.PublicKey, KID: "sig-2"}},
   ```

2. Wait at least an hour, so Singpass has fetched S2.
3. Deploy with `SigningKey: s2, SigningKID: "sig-2"` and no additional keys.

**Encryption key** (E1 → E2): publish E2 in place of E1, and decrypt with both
until Singpass has stopped using E1. Tokens carry the key's `kid` in their JWE
header, and the client decrypts with the key it names.

1. Deploy with E2 as the current, published key, and E1 kept for decryption
   only:

   ```go
   EncryptionKey: e2, EncryptionKID: "enc-2",
   AdditionalEncryptionKeys: []singpass.DecryptionKey{
       {Key: e1, KID: "enc-1", DecryptOnly: true},
   },
   ```

2. Wait at least an hour: tokens may arrive encrypted to either key meanwhile.
3. Deploy without E1.

Every key needs a new `kid`. With HSM/KMS keys, use `PublishedKey` with the
key's public half, and `DecryptionKey.Agreer` in place of `Key`; if you inject
`Dependencies.Keys` or `Dependencies.Decryption` yourself, build them with
`singpass.NewRotatingKeyManager` and `singpass.NewRotatingDecrypter`. For a JWKS
published as a static file, `singpass.OfflineJWKS` builds it from the public
keys, listing every published key.
