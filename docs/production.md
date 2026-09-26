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
- [ ] **Production redirect URIs**, over `https`, registered exactly as the app
      sends them. They must not contain "singpass", "corppass" or "myinfo" (see
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

## 3. Durable session stores

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

- [ ] **Serve over HTTPS** and set `web.DefaultCookieConfig(true)`, or
      `Cookies.Secure = true`.
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
- [ ] **Keep clocks in sync (NTP).** Token and DPoP validation compare
      timestamps, allowing only small skew.
- [ ] **Monitor login outcomes:** denied, expired and failed rates, and errors
      calling `id.singpass.gov.sg`.
- [ ] **Stay current.** Watch the repository's releases, and read the
      [CHANGELOG](../CHANGELOG.md) before upgrading: pre-1.0 minor versions may
      change the API. Security fixes are announced as GitHub security
      advisories.
