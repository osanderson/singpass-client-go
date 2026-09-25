# Singpass Login + Myinfo — integration quirks

> Non-obvious behaviours hit while building this demo against **Singpass staging**
> (FAPI 2.0, issuer `https://stg-id.singpass.gov.sg/fapi`). These are Singpass
> behaviours you must *know* to configure correctly — FAPIgo handles the
> mechanics, but it can't guess these for you. Companion to `corppass-quirks.md`.

## Discovery

- **There are two discovery documents — use the FAPI one.** The generic OIDC
  metadata at `.../.well-known/openid-configuration` is *not* the FAPI profile.
  The FAPI issuer is `https://stg-id.singpass.gov.sg/fapi`, and its metadata lives
  at `https://stg-id.singpass.gov.sg/fapi/.well-known/openid-configuration`.
  Pointing at the non-FAPI document yields endpoints that don't behave like the
  PAR/DPoP FAPI stack. **This was the first hiccup.**

## Clients & onboarding

- **Login and Myinfo are the *same* issuer but *separate* clients.** One
  authorization server, but each product is onboarded with its own `client_id`
  **and** its own signing/encryption key pair. You register two JWKS and run two
  redirect URIs. (This demo runs both relying parties in one server, namespaced
  `/login/*` and `/mi/*`.)
- **Redirect URIs may not contain "singpass", "corppass" or "myinfo"**
  (case-insensitive). The onboarding portal rejects them ("Invalid redirect URL.
  Please do not include the substrings …"), and its guidance says the *domain* must
  not use the product names — so a Cloud Run service can't be called
  `singpass-demo`. Whether the path is checked too is unclear (older localhost
  URIs with `/myinfo/` in the path were accepted), so the demo avoids the words
  everywhere: it deploys as Cloud Run service `rp-demo` and routes Myinfo under
  `/mi/*` and Myinfo Business under `/mib/*`.
- **Myinfo scopes are per-data-item, not a single `myinfo` scope.** Each field is
  its own scope (`name`, `dob`, `uinfin`, `birthcountry`, …) and every one must be
  whitelisted on that client. Requesting a scope the client isn't approved for is
  rejected.
- **`acr_values` is rejected unless your client is whitelisted for it.** Omit it by
  default.
- **Redirect URI must match exactly**, including the per-app path. A path change
  (e.g. `/callback` → `/login/callback`) is a re-registration, independent of any
  key change.

## Authorization / PAR request

- **`authentication_context_type` is a Login-only parameter**
  (`APP_AUTHENTICATION_DEFAULT`). Sending it on a **Myinfo** request is rejected:

  > `invalid_request`: *authentication_context_type and
  > authentication_context_message can only be provided for Login apps. Please
  > remove these fields from your request body.*

  So it must be set for Login and **omitted** for Myinfo. The product
  constructors handle this: `singpass.NewLogin` sends it (defaulting to
  `APP_AUTHENTICATION_DEFAULT`), while `singpass.NewMyinfo` and `singpass.NewMyinfoBusiness`
  never do.
- **PAR requires `client_id` in the body** even with `private_key_jwt`
  authentication (strict AS).
- **The DPoP binding must be committed at PAR**, not only at the token endpoint.
  FAPIgo does this by sending a DPoP proof in a `DPoP` header on the PAR request
  (RFC 9449 §10.1, `client.PARDPoPBindingProof`); Singpass accepts it.

## Crypto / JWE (the algorithm gotchas)

- **The id_token is encrypted (JWE wrapping a JWS), not a plain JWT.**
  Signed-then-encrypted; a plain id_token is refused.
- **id_token and `/userinfo` use *different* content-encryption algorithms.** Both
  use `ECDH-ES+A256KW` key wrap and an `ES256` inner signature, but:
  - id_token content encryption: **`A256CBC-HS512`**
  - Myinfo `/userinfo` content encryption: **`A256GCM`**

  A single integration must accept **both**. Pinning to one silently breaks the
  other flow — this was the "Something went wrong completing the Myinfo login"
  failure (userinfo decrypt rejected `A256GCM` when constrained to `A256CBC-HS512`).
- Everything is **ES256 / P-256** — no RSA in play.

## Myinfo `/userinfo` (the extra hop)

- **Myinfo needs a second call after token issuance.** The id_token only proves
  *who* logged in; person data lives behind the DPoP-protected `/userinfo`
  endpoint. FAPIgo makes this call natively via `Client.FetchUserInfo`. The
  caller only declares the UserInfo algorithms
  (`Config.Algorithms.UserInfo` / `UserInfoKeyManagement` / `UserInfoContentEncryption`);
  the endpoint rides along in `discovered.Endpoints`.
- **`/userinfo` is DPoP-bound**: `Authorization: DPoP <access_token>` **plus** a
  DPoP proof JWT carrying `ath` (base64url SHA-256 of the access token), `htu`,
  `htm`, `iat`, `jti`. The proof must be signed with the **same ephemeral DPoP
  key** the access token was bound to at the token endpoint (its JWK thumbprint
  must match the token's `cnf.jkt`).
- **The resource-server nonce is separate from the AS nonce.** `/userinfo` can
  answer `401` + `DPoP-Nonce`; retry once, echoing that nonce in a fresh proof
  (RFC 9449 §9 — resource-server nonce; §8 is the AS's).
- **Person data is under the `person_info` claim** in the decrypted + inner-JWS-
  verified response; standard `iss` / `aud` (must contain your `client_id`) / `sub`
  still apply and should be checked before trusting it.
- **Every data item is wrapped in an envelope.** A field carries either a `value`
  (most fields) or a `code` + human `desc` (coded fields — `sex`, `nationality`,
  `residentialstatus`, …), plus `source` (`1` government-verified, `2`
  user-provided, `3` not applicable, `4` verified), `classification`, and
  `lastupdated` (YYYY-MM-DD). An item the source cannot provide is flagged
  `"unavailable": true` with no value. Addresses (`regadd`) and phone (`mobileno`)
  are nested objects; some records are arrays. The library's `myinfo.Response` /
  `myinfo.Data` / `myinfo.Field` accessor (`myinfo/myinfo.go`) understands all of this; the
  full Person schema is Singpass's "Get Person" OpenAPI (integration guide §5 /
  the personal data catalog). Corppass Myinfo Business double-encodes its blocks —
  see [corppass-quirks.md](corppass-quirks.md).
- **Envelope metadata lives on containers and records, not only leaves.** For a
  *grouped* dataset (`noa-basic`, `drivinglicence`, `cpfinvestmentscheme`, `regadd`,
  …) Myinfo declares `source` / `classification` / `lastupdated` on the **container
  object**, while the value leaves inside carry only `{value}`; and each record in a
  repeated-record array (a licence, an appointment) is itself an envelope declaring
  its own `source` as a sibling of its leaves. So provenance is read from the object,
  not a field — the library exposes this as `myinfo.Data.Source()` / `SourceCode()` /
  `Classification()` / `ClassificationCode()` / `LastUpdated()` (mirroring the `Field`
  methods), so a caller need not reach into `Raw()` and re-parse the `1`..`4` code
  table. To dispatch a **generic walk** over a block without inspecting the raw map,
  `myinfo.Data.Kind(key)` reports the envelope shape (`KindLeaf` / `KindObject` /
  `KindList` / `KindScalar` for bare envelope-metadata scalars / `KindAbsent`).

## Token response

- **The token response omits `scope` (Singpass ≠ Corppass).** RFC 6749 §5.1 makes
  the token endpoint's `scope` optional *when the granted scope equals the requested
  scope*. **Singpass Login and Myinfo omit it**; **Corppass Myinfo Business echoes
  the full granted scope** (see [corppass-quirks.md](corppass-quirks.md)). So an RP
  that reads the response `scope` verbatim shows an empty scope for Singpass but a
  populated one for Corppass — an easy inconsistency to trip over. Per that RFC rule
  the correct reading is: an absent `scope` means *granted == requested*, so fall
  back to the requested scope. The library does this in `Client.Complete`
  (`Identity.Scope`), so callers get the effective granted scope for both issuers.
  (Singpass models data it cannot supply as `{"unavailable":true}` inside
  `/userinfo`, not by narrowing scope, so granted really does equal requested here.)

## Non-Singpass gotcha worth noting

- **`.env` sourcing needs quoted scope values.** Space-separated scope lists must
  be quoted, or `set -a; . ./.env` runs the trailing words as shell commands
  (`command not found: mobileno`). Not a Singpass issue, but the long
  space-separated Myinfo scope list makes it easy to trip over.

## References

- RFC 9126 — Pushed Authorization Requests (PAR)
- RFC 9449 — DPoP: §4 (proof), §7 (protected-resource access, `ath`), §8 / §9
  (authorization-server / resource-server `DPoP-Nonce`), §10.1 (DPoP with PAR)
- RFC 7518 §5.2.5 (`A256CBC-HS512`), §5.3 (`A256GCM`) — the two content encryptions
- OIDC Core §5.3 — UserInfo endpoint; §5.3.2 — signed/encrypted UserInfo response
- Singpass developer docs — Login and Myinfo product guides
