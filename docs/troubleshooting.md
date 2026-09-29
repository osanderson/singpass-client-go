# Troubleshooting

Find the symptom, then the cause and the fix. Errors from Singpass or Corppass
end with the server's error code, e.g.

```
singpass: begin authorization: client: invalid_response: no matching client key: authorization server error: invalid_client
```

— here the pushed authorization request (PAR, sent by `BeginLogin`) failed
with `invalid_client`. Errors from `Complete` come from the token or
`/userinfo` call. In code, `singpass.ErrorCode(err)` returns the code,
`singpass.ServerError(err)` the full response (code, description, HTTP
status), and `singpass.IsTemporary(err)` whether trying again may help. The codes and meanings below follow Singpass's
[error tables](https://docs.developer.singpass.gov.sg/docs/technical-specifications/integration-guide);
Corppass uses the same codes.

## At startup

| Symptom | Cause | Fix |
|---|---|---|
| `singpass: …` naming an option (`RedirectURI`, `Scopes`, `kid is required`, …) | The constructor's option checks | Fix the option it names; every problem is listed at once. See [configuration.md](configuration.md#validation). |
| `discover metadata` fails | The issuer URL is wrong or unreachable | Use the library's defaults: the Singpass issuer ends in `/fapi`, Corppass's doesn't ([singpass-quirks.md](singpass-quirks.md#discovery)). Check outbound HTTPS to `stg-id.singpass.gov.sg` / `id.singpass.gov.sg`. |
| `AssuranceProduction` refuses the session store | Production needs a durable store | Set `Dependencies.Sessions`, e.g. from `sqlstore` ([production.md](production.md)). |

## At `BeginLogin` (PAR)

| Error code | Cause | Fix |
|---|---|---|
| `invalid_client` | Singpass couldn't verify the client assertion: the registered JWKS doesn't hold the signing key under that `kid`, or the client ID is wrong or the app isn't active | Check the published JWKS with `client.CheckPublishedJWKS(ctx, url)` or `singpass-keygen -check <url>`; with a JWKS object, compare it with `client.PublicJWKS`. Check `ClientID` is this app's, for this environment (staging and production IDs differ). |
| `invalid_scope` | `openid` is missing, or a scope isn't in the app's allowed scopes | Request only allowed scopes, or add the scope to the app in the portal (reviewed in production). |
| `invalid_request` naming the redirect URI | `RedirectURI` isn't registered for the app, character for character | Register it in the portal, or fix the option. |
| `invalid_request` about `authentication_context_type` | Sent on a Myinfo app | Use `NewMyinfo` / `NewMyinfoBusiness`, which never send it. |
| `invalid_request` about `acr_values` | The app isn't allowed to request it | Leave `AcrValues` empty. |
| `invalid_dpop_proof` | The DPoP proof was rejected, usually because the server's clock and yours differ | Keep the host's clock synced (NTP). |
| `upstream_dependency_error` | Singpass couldn't fetch your JWKS endpoint | Make it public `https` with a publicly trusted certificate, with no redirect, IP allow-list or mTLS, answering within 3 seconds; `CheckPublishedJWKS` tests most of this. Otherwise it's transient: retry up to 3 times with backoff (`Dependencies.BeginLoginRetries`). |
| `server_error`, `temporarily_unavailable` | A problem at Singpass | Set `Dependencies.BeginLoginRetries` (up to 3) to retry with backoff, then show a "try again later" page. |

## At the callback (`Complete`)

| Symptom | Cause | Fix |
|---|---|---|
| `errors.Is(err, singpass.ErrLoginExpired)` | The login state is unknown, used or expired: the callback was reloaded or replayed, came after the login timed out, or arrived without this browser's login state — the `state` passed to `Complete`, e.g. in another browser | Show "please try again" and restart the login. It isn't a fault. |
| `*singpass.DeniedError` | The user cancelled, or Singpass returned an error to the redirect URI (`server_error`, `temporarily_unavailable`) | Show a friendly page. Don't display the error description verbatim ([Singpass advises against it](https://docs.developer.singpass.gov.sg/docs/technical-specifications/integration-guide/2.-handling-the-redirect)). |
| `invalid_grant` | The code was exchanged more than 60 seconds after it was issued, or the redirect URI differs from the one sent at PAR | Complete the callback promptly; don't change `RedirectURI` between `BeginLogin` and `Complete`. |
| `invalid_client` | As at PAR: the JWKS or client ID | As at PAR. |
| Decryption fails, or `token is encrypted to kid …, but this client holds …` | The id_token or `/userinfo` response is encrypted to a key the client doesn't hold: the registered JWKS has an encryption key the app wasn't given, often mid-rotation | Give the client every published encryption key ([production.md](production.md#7-rotating-keys)). |
| `/userinfo` fails with `invalid_request` | Your JWKS couldn't be fetched, or the user has a Singpass Foreign Account, which has no Myinfo data | Check the JWKS as above. For foreign-account users, offer another way to provide the data. On staging, try a different test persona. |
| `/userinfo` fails with `invalid_token` | The access token expired (30 minutes) | `Complete` fetches `/userinfo` straight after the token; this points to a stalled request. |
| `/userinfo` subject mismatch on Myinfo Business | Corppass once sent the client ID as the `/userinfo` subject | It no longer does; if an environment still does, set `TolerateUserInfoSubjectClientID` ([corppass-quirks.md](corppass-quirks.md)). |

## In the portal

| Symptom | Cause | Fix |
|---|---|---|
| The redirect URL is refused | It contains "singpass", "corppass" or "myinfo" ("Invalid redirect URL…"), or uses an IP address | Rename the host or path; use `localhost`, not `127.0.0.1`, for local development ([onboarding.md](onboarding.md#3-create-a-staging-app)). |
| A pasted JWKS object is refused | Singpass requires at least one signing (`use: sig`) and one encryption (`use: enc`) EC key, each with a unique `kid` | Paste the output of `singpass-keygen` (with `-sig`/`-enc` for several keys) or `singpass.OfflineJWKS`. Never include private key members such as `d`. |

## Still stuck

Turn on `Dependencies.Debug` against **staging only** — it logs the PAR,
token and `/userinfo` requests and responses, including the client
assertion — and compare them with the
[Singpass integration guide](https://docs.developer.singpass.gov.sg/docs/technical-specifications/integration-guide).
To rule out your environment, run the same flow against `singpasstest` (or,
from an app in another language, `singpass-fake-server`), or the demo with
`DEMO_MOCK=1`.
