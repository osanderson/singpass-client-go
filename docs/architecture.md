# How it works

This library is a thin layer over the [FAPIgo](https://github.com/idfoundry/fapigo)
relying-party engine, which drives the whole FAPI 2.0 protocol. This page
explains what Singpass and Corppass need beyond the generic flow, and which
piece handles each part. For the non-obvious server behaviours behind these
choices, see [singpass-quirks.md](singpass-quirks.md) and
[corppass-quirks.md](corppass-quirks.md).

Singpass Login and Myinfo are the **same** FAPI 2.0 authorization server
(`id.singpass.gov.sg`); Myinfo Business is a **separate** authorization server run
by Corppass (`id.corppass.gov.sg`). Each product is onboarded as its **own client**
— its own `client_id` and its own signing/encryption key pair.

> **No Singpass-specific protocol shims.** FAPIgo sends the full PAR request
> (`client_id`, the plain-string `authentication_context_type` / `acr_values`
> parameters, and a DPoP proof binding the code to the DPoP key), decrypts the
> encrypted (JWE) `id_token` and exposes its validated claims, and makes the
> DPoP-protected `/userinfo` call. This library supplies only key material and
> small hooks — a `keys.KeyManager` (signs client assertions + DPoP proofs), a
> `keys.Decrypter` assembled from FAPIgo's own helpers, and a
> `storage.SessionStore`. There is **no JOSE code of its own**.

## Where each Singpass/Corppass requirement is handled

FAPIgo drives the generic FAPI 2.0 flow. Singpass differs from that baseline in a
few places, all handled inside FAPIgo with small hooks this library supplies:

1. **PAR request parameters (outbound) — sent by FAPIgo,** so there is no outbound
   request rewriting:
   - `client_id` — top-level PAR parameter (RFC 6749 §4.1.1 / RFC 9126).
   - **DPoP binding at PAR** — FAPIgo sends a DPoP proof in a `DPoP` header on the
     PAR request (RFC 9449 §10.1, `client.PARDPoPBindingProof`), binding the
     authorization code to the DPoP key it will use at the token endpoint.
     Singpass requires this binding up front.
   - `authentication_context_type` — required for **Login** apps
     (`APP_AUTHENTICATION_DEFAULT` for a standard login) and **rejected** on Myinfo
     / Myinfo Business requests. `NewLogin` sets it; `NewMyinfo` /
     `NewMyinfoBusiness` omit it. It rides as a plain-string FAPIgo *extension*
     ([`extensions.go`](../extensions.go)), emitted as a top-level PAR parameter on the FAPI 2.0
     baseline profile.
   - `acr_values` — via `Options.AcrValues`, only if set (Singpass rejects it
     unless your client is whitelisted for it).

2. **Encrypted `id_token` (inbound) — driven by FAPIgo.** Singpass returns a JWE
   wrapping a JWS (`ECDH-ES+A256KW` + `A256CBC-HS512`). This library declares those
   algorithms and provides a `keys.Decrypter` built from FAPIgo's
   `keys.NewSingleKeyDecrypter` / `keys.NewInMemoryECDH` ([`decrypter.go`](../decrypter.go)).
   FAPIgo parses the compact JWE, delegates only the ECDH primitive to that
   decrypter to recover the content-encryption key, decrypts the payload, checks
   `cty=JWT`, and verifies the inner JWS itself. Declaring the algorithms also
   enables FAPIgo's **downgrade protection**: a plain (unencrypted) `id_token` is
   rejected. The validated claims land on `Identity.Claims`.

Everything else — PKCE S256, `private_key_jwt`, the token-endpoint DPoP proof,
`iss` checking (RFC 9207), and the id_token's own signature / iss / aud / nonce /
exp validation — is FAPIgo's.

## Myinfo and `/userinfo`

The id_token only proves *who* logged in; person data lives behind the
DPoP-protected `/userinfo` endpoint. When `FetchUserInfo` is set, `Complete` calls
FAPIgo's native `Client.FetchUserInfo`, which: makes the DPoP-bound `GET` (RFC
9449, with `ath`), retries once on a `401` + `DPoP-Nonce` challenge (§9), decrypts
the response JWE (`ECDH-ES+A256KW` / **`A256GCM`** — note the content encryption
differs from the id_token's `A256CBC-HS512`) through the same `keys.Decrypter`
(which serves both `IDTokenDecryption` and `UserInfoDecryption`), verifies the
inner issuer JWS (`ES256`), and checks the response `sub`. The validated result is
exposed on `Identity.Myinfo` (see the [README](../README.md#myinfo-person-data)).

## Myinfo Business (Corppass)

Protocol-wise identical to Myinfo — PAR, DPoP, `private_key_jwt`, PKCE, encrypted
`id_token`, DPoP-protected `/userinfo`, same algorithms. The differences are
configuration, encoded in `NewMyinfoBusiness`:

- **Different issuer** — `id.corppass.gov.sg`, with **no `/fapi` path suffix**
  (Singpass uses `id.singpass.gov.sg/fapi`). Defaults to `singpass.StagingCorppassIssuer`.
- **Scope namespaces** — `entity.*` (organisation), `user.*` (person),
  `corppass.*` (Corppass account); each must be whitelisted on the client.
- **Multiple `/userinfo` blocks** — the response can carry `entity_info`,
  `person_info`, `corppass_info`, `auth_info`, `tp_auth_info`, each a nested object.
  `Identity.Myinfo` exposes each one as its own `Data` block (`Person`, `Entity`,
  `Corppass`, `Auth`, `TPAuth`; see [`myinfo/myinfo.go`](../myinfo/myinfo.go)) — personal Myinfo fills only
  `Person`. Corppass also double-encodes some blocks (and nested objects) as
  stringified JSON; these are unwrapped recursively, so every block reads as real
  nested JSON.
- **`sub == client_id` tolerance** — Corppass sets the `/userinfo` `sub` to the
  `client_id` (an OIDC Core §5.3.2 deviation); `NewMyinfoBusiness` opts into
  accepting it.

## Keys and limits

- **Ephemeral DPoP key.** The DPoP proof key is generated per `KeyManager` and
  registered nowhere — sender-constraining and correctly non-persistent. It signs
  the DPoP proof at PAR, the token request and `/userinfo`, so all three match the
  token binding.
- **JOSE size cap.** FAPIgo bounds the compact JWS/JWE size it will parse. The
  default `RecommendedLimits` raises `MaxJOSECompactBytes` to 256 KiB
  ([`limits.go`](../limits.go)), since a full-scope Myinfo `/userinfo` response runs well past
  the 16 KiB baseline; fixed-shape artifacts (DPoP proofs, client assertions) are
  unaffected.
