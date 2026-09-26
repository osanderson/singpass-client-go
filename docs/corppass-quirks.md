# Myinfo Business (Corppass) — integration quirks

> Corppass runs Myinfo Business on its **own** FAPI 2.0 authorization server,
> separate from Singpass. Protocol-wise it is the same profile FAPIgo already
> drives for Singpass (PAR + DPoP + `private_key_jwt` + PKCE + encrypted
> `id_token` + DPoP-protected `/userinfo`), so the demo adds it as a third client
> (`/mib/*`) with no new protocol code. What differs is all configuration,
> plus one caller opt-in for a `/userinfo` `sub` deviation (see below). FAPIgo
> handles Corppass's spec-permitted (and issuer-specific) JWE-header and JWKS
> variations natively. Companion to `singpass-quirks.md`. Verified **end-to-end
> against Corppass staging** (`https://stg-id.corppass.gov.sg`): full browser
> login renders `entity_info` / `auth_info`.

## Discovery / issuer

- **Separate issuer, no `/fapi` suffix.** The Corppass FAPI issuer is
  `https://stg-id.corppass.gov.sg` (staging) / `https://id.corppass.gov.sg`
  (production) — note there is **no `/fapi` path**, unlike Singpass
  (`https://stg-id.singpass.gov.sg/fapi`). Discovery is at
  `{issuer}/.well-known/openid-configuration`; every endpoint (PAR, authorize,
  token, userinfo, jwks) comes from there.

## Clients & onboarding

- **A distinct client on the Corppass portal.** Myinfo Business is onboarded on
  the Corppass Developer Portal (not the Singpass portal), with its own
  `client_id` and its own signing/encryption key pair. The demo registers a
  separate JWKS (`keys/myinfobiz/*`) and redirect URI (`/mib/callback`).
- **Scopes are namespaced by data category** and each must be whitelisted:
  - `entity.*` — organisation data → returned under `entity_info`
    (e.g. `entity.basic_profile.name`)
  - `user.*` — person data → returned under `person_info` (e.g. `user.name`)
  - `corppass.*` — Corppass account data → returned under `corppass_info`
    (e.g. `corppass.email`)
  - `authinfo` — the authorisations the user holds → returned under `auth_info`
  - `tpauthinfo` — third-party authorisation info → returned under `tp_auth_info`
  `openid` is still required.
- **Only whitelisted scopes are accepted.** The token endpoint rejects any scope not
  registered for the client (`invalid_scope: requested scope is not allowed`). The
  demo's `MYINFO_BIZ_SCOPES` is the exact whitelisted set for its staging client —
  here `entity.*` + `entity.identity` + `authinfo` + `tpauthinfo` + `openid`, and
  **no** `user.*` / `corppass.*`; the returned blocks are `entity_info` + `auth_info`
  accordingly.

## Authorization / PAR request

- **`authentication_context_type` is Corppass-Login-only.** Exactly as on Singpass,
  Corppass rejects it (and `authentication_context_message`) on a Myinfo Business
  request. `singpass.NewMyinfoBusiness` therefore never sends it (the demo's `mib`
  app sets no `AuthContextType`).
- PAR, `client_id` in the body, and the DPoP binding at PAR (a `DPoP` proof
  header) behave as on Singpass — all sent by FAPIgo.

## Crypto / JWE

- **Same algorithms as Singpass.** Inner JWS `ES256` (P-256); key management
  `ECDH-ES+A256KW`; content encryption `A256CBC-HS512` for the `id_token` and
  `A256GCM` for `/userinfo` — the same id_token-vs-userinfo asymmetry the Singpass
  integration already handles. The existing `keys.Decrypter` serves both issuers
  unchanged.
- **JWE protected headers carry extra members.** The `id_token` header adds `iss` /
  `aud` (plus a correct `cty:"JWT"`); the `/userinfo` header adds `typ:"JWE"` and
  **omits `cty`**. FAPIgo tolerates both — its header parser ignores the unknown
  members and it does not require `cty` on the nested JWT.
- **JWKS is served as `application/jwk-set+json`** (RFC 7517 §8.5.1) and its single
  EC signing key carries `x5c` / `x5t` / `x5t#S256`. FAPIgo accepts that content
  type and ignores the certificate members.
- **Longer-lived `id_token`.** Corppass's `id_token` exp–iat span exceeds Singpass's;
  `singpass.RecommendedLimits` sets `Limits.MaxIDTokenLifetime` to one hour to allow for
  it.

## Token response

- **`scope` is echoed (unlike Singpass).** Corppass's token endpoint returns the
  full granted `scope` in the token response, whereas Singpass Login/Myinfo omit it
  (both are spec-legal — RFC 6749 §5.1 makes `scope` optional when granted ==
  requested). An RP reading the response `scope` verbatim therefore sees a populated
  value for Corppass but an empty one for Singpass Myinfo; the library normalises
  this by falling back to the requested scope when the response omits it
  (`Client.Complete` → `Identity.Scope`). Cross-reference:
  [singpass-quirks.md](singpass-quirks.md).

## `/userinfo` response

- **Multiple data blocks, not just `person_info`.** The decrypted, inner-JWS-
  verified response can carry several top-level claims, selected by the requested
  scopes:
  - `entity_info` — organisation data
  - `person_info` — the logged-in person's data
  - `corppass_info` — Corppass account data
  - `auth_info` — the authorisations the user holds
  - `tp_auth_info` — third-party authorisation info

  The library surfaces every recognised block through the envelope-aware
  `myinfo.Response` / `myinfo.Data` / `myinfo.Field` accessor (`myinfo/myinfo.go`).
- **Block internals (verbatim keys).** `entity_info` is **not just
  `basic_profile`** — that sub-object holds the scalar/coded scalars (entity name
  `entity_info.basic_profile.name.value`, company_type, uen_status, activities, …,
  each a Myinfo envelope, scope-driven), but the block also carries, as siblings of
  `basic_profile`:
  - `address` — a nested Myinfo address object (envelope leaves `block` / `street` /
    `building` / `floor` / `unit` / `postal`, coded `country`), the entity
    counterpart of a person's `regadd`;
  - repeated-record **arrays** of envelope objects — `appointments`,
    `shareholders`, `capitals`, `financials`, `licences` (and, when in scope but
    often empty, `builders` / `contractors` / `grants`). An appointment/shareholder
    nests its party under `individual_appointment` / `entity_appointment` (resp.
    `individual_shareholder` / `entity_shareholder`), each with an envelope `name`;
    financial figures are envelope leaves whose `value` is a **JSON number**
    (`Field.Value()` formats it), e.g. `financials[].company_financial.revenue.value`;
  - `history` — `{previous_names[], previous_registration_numbers[]}`, each a small
    envelope-object array.
  All of these are only reachable/renderable via the accessor's nested `Object` /
  `List` navigation, not by iterating `basic_profile` alone. `auth_info` is a
  bespoke nested shape, **not** the Myinfo envelope: `Result_Set.ESrvc_Result[]`,
  each with `CPESrvcID` and `Auth_Result_Set.Row[]`, each row `{CPEntID_SUB, CPRole,
  StartDate, EndDate, Parameter[]}` (PascalCase/underscore keys). `Data.Authorisations()`
  (`myinfo/authinfo.go`) hides those key names: it flattens the block into a
  `[]myinfo.Authorisation` (one per `Row`, each tagged with its parent `CPESrvcID`), and
  works for both `Response.Auth` and `Response.TPAuth` (`id.Myinfo.Auth` /
  `.TPAuth`) — returning nil for an absent or wrong-shaped block so callers can fall
  back to `Raw()`. Being a plain record, an `Authorisation` carries no envelope
  metadata (no source/classification/lastupdated). The `person_info` block, when
  present (needs `user.*` scopes), follows the Singpass personal Person schema.
- **Blocks are stringified JSON (double-encoded).** Each block value is a JSON
  *string* whose contents are themselves a JSON object — e.g. `entity_info` arrives
  as `"{\"basic_profile\":{…}}"`, not `{"basic_profile":{…}}`, and some nested
  objects inside a block are double-encoded the same way. The library unwraps any
  stringified JSON object or array, recursively (`unwrapDeep` in `myinfo/myinfo.go`),
  so `myinfo.Response` and `Raw()` expose real nested JSON.
- **`sub` is the `client_id`, not the subject.** Contrary to OIDC Core §5.3.2, the
  `/userinfo` `sub` equals the `client_id` (the response is entity data authorized to
  the client). In the `id_token`, `sub` is the **entity** — its registration number
  (e.g. a UEN), with `sub_type: "entity"` and `sub_attributes` describing it
  (`entity_type`, `entity_reg_number`, `entity_coi`, `entity_name`,
  `entity_uen_status`) — and the person who logged in is the `act` claim (`sub` = their
  Singpass UUID, `sub_type: "user"`, `sub_attributes` with `account_type`,
  `identity_number`, `identity_coi`, `name`; `Identity.ActingParty()`). FAPIgo accepts
  `sub == client_id` via the opt-in `Config.TolerateUserInfoSubjectEqualsClientID`
  — `singpass.NewMyinfoBusiness` turns it on
  (`Options.TolerateUserInfoSubjectClientID`), while `NewLogin` / `NewMyinfo` leave
  it off, so Login/Myinfo stay strict. `iss` / `aud` and the inner JWS are validated
  by FAPIgo as usual; the returned `Subject` is still the id_token's verified `sub`.
- **DPoP-bound**, with the same `ath` proof and `DPoP-Nonce` retry as Singpass
  Myinfo — handled by FAPIgo's native `FetchUserInfo`.

## References

- Corppass Authorization API (FAPI 2.0): https://docs.corppass.gov.sg/technical-specifications/corppass-authorization-api-fapi-2.0
- Myinfo Business scopes: https://docs.corppass.gov.sg/technical-specifications/corppass-authorization-api-fapi-2.0/scopes/myinfo-business-scopes
- Userinfo endpoint / data blocks: https://docs.corppass.gov.sg/technical-specifications/corppass-authorization-api-fapi-2.0/integration-guide/4.-userinfo-endpoint
- Authentication context parameters (Login-only): https://docs.corppass.gov.sg/technical-specifications/corppass-authorization-api-fapi-2.0/integration-guide/1.-pushed-authorization-request-par-endpoint/authentication-context-parameters
