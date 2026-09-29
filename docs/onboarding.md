# Onboarding

From nothing to a working staging login, and on to production. Each step
names the portal setting and the library option it corresponds to.

No staging client yet? Try the library first with the fake server:
`DEMO_MOCK=1` in [`examples/demo`](../examples/demo), or `singpasstest` in
your own tests.

## 1. Get portal access

Singpass Login, Myinfo **and Myinfo Business** apps are all created in the
[Singpass Developer Portal](https://developer.singpass.gov.sg) (SDP) — Myinfo
Business too, even though its issuer is Corppass. Request access for your
organisation first
([how](https://docs.developer.singpass.gov.sg/docs/singpass-developer-portal-sdp/getting-access/obtaining-access-to-the-singpass-developer-portal-sdp)).

## 2. Create your keys

Each app has its own signing key and encryption key:

```sh
go install github.com/osanderson/singpass-client-go/cmd/singpass-keygen@latest
singpass-keygen -dir keys/login -sig-kid login-sig-1 -enc-kid login-enc-1 > login.jwks.json
```

Keep `keys/` out of version control. For production, prefer HSM/KMS-held keys
([configuration.md](configuration.md#keys)).

## 3. Create a staging app

Create a staging app for the product in SDP
([how](https://docs.developer.singpass.gov.sg/docs/singpass-developer-portal-sdp/app-management/create-staging-app)),
and fill in its configuration:

| Portal setting | What to enter | In the library |
|---|---|---|
| Product | Login, Myinfo or Myinfo Business | `NewLogin`, `NewMyinfo` or `NewMyinfoBusiness` |
| Redirect URL | Your callback URL, exactly as the app sends it | `RedirectURI` |
| Token-based authentication | A JWKS endpoint or a JWKS object (below) | the keys from step 2 |
| Allowed scopes | The data items the app needs, plus `openid` | `Scopes` |
| — | The app's client ID, shown once it's created | `ClientID` |

**Redirect URL.** Use `https`, or `http://localhost` for local development on
staging. The portal rejects URLs with an IP address (so not `127.0.0.1`) and
URLs containing "singpass", "corppass" or "myinfo" — keep those words out of
the domain and path. With the `web` helper the callback is
`https://<your host>/<App.Name>/callback`.

**JWKS endpoint or JWKS object.** Singpass needs your public keys, either way:

- **JWKS endpoint** — a URL Singpass fetches your JWKS from. The `web` helper
  serves it at `/<App.Name>/jwks.json` (from `Client.PublicJWKS`). The URL must
  be public `https` with a publicly trusted certificate, must not redirect, and
  must answer within 3 seconds. Singpass caches it for up to an hour, so a key
  change reaches Singpass without touching the portal, and
  `client.CheckPublishedJWKS` can confirm it's right.
- **JWKS object** — paste the JWKS itself (`login.jwks.json` from step 2) into
  the portal. Nothing to host, but every key change — including each step of a
  [key rotation](production.md#7-rotating-keys) — is an edit to the app in the
  portal. `singpass-keygen -sig PATH=KID … -enc PATH=KID …` prints the set to
  paste when it lists several keys.

The endpoint is easier to operate once live; the object is quicker to start
with. Either way the JWKS holds public keys only — never paste a private key.

**Scopes.** Myinfo scopes are per data item (`name`, `uinfin`, `regadd`, …);
see the [Myinfo data catalogue](https://docs.developer.singpass.gov.sg/docs/data-catalog-myinfo/catalog)
and the [Myinfo Business scopes](https://docs.corppass.gov.sg/technical-specifications/corppass-authorization-api-fapi-2.0/scopes/myinfo-business-scopes).
Request only scopes the app is allowed; others fail at login.

## 4. Connect and log in

```go
client, err := singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
    ClientID:    "your-staging-client-id",
    RedirectURI: "https://app.example.com/mi/callback",
    Scopes:      []string{"openid", "name", "uinfin", "regadd"},
    SigningKey:  sig, SigningKID: "myinfo-sig-1",
    EncryptionKey: enc, EncryptionKID: "myinfo-enc-1",
}, singpass.Dependencies{}) // staging defaults
```

The constructor checks the options before contacting Singpass and names any
problem. With a JWKS endpoint, run `client.CheckPublishedJWKS(ctx, url)` once
deployed. Then log in with a staging test account: the
[Myinfo test personas](https://docs.developer.singpass.gov.sg/docs/testing/myinfo-test-personas)
or the [Myinfo Business test personas](https://docs.corppass.gov.sg/testing/myinfo-business-test-personas).
If it fails, see [troubleshooting.md](troubleshooting.md).

## 5. Production

A production app is a separate app with its own client ID, keys and
configuration. Before creating it, SDP requires agreeing to the Singpass
Services Agreement, billing contact details and a user journey for review;
approval can take up to two weeks, and each additional production scope is
reviewed. Then work through the [go-live checklist](production.md).
