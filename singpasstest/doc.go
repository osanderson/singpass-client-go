// Package singpasstest runs a fake Singpass or Corppass FAPI 2.0 authorization
// server in-process, so an integration can be tested — or demoed — without
// onboarding, network access or real accounts.
//
// It is built on FAPIgo's own authorization-server engine, so the protocol is
// genuine: pushed authorization requests with DPoP, private_key_jwt client
// authentication, PKCE, an ES256-signed id_token encrypted to the client
// (ECDH-ES+A256KW / A256CBC-HS512), and a DPoP-protected /userinfo that is
// signed and encrypted (A256GCM). On top it reproduces the Singpass/Corppass
// behaviours this library handles:
//
//   - Singpass issuers end in "/fapi"; Corppass issuers don't.
//   - authentication_context_type is required for Login clients and rejected
//     for Myinfo clients.
//   - Singpass omits "scope" from the token response; Corppass echoes it.
//   - Singpass /userinfo returns only the person_info items the granted scopes
//     cover.
//   - Corppass /userinfo sends each block as double-encoded JSON (and, with
//     Config.CorppassUserInfoSubClientID, Corppass's former "sub" = client_id
//     deviation).
//   - id_tokens carry "sub_type" and "sub_attributes" — on Singpass released
//     per scope (user.identity, name, email, mobileno); on Corppass the entity
//     is the subject and the acting person is the "act" claim.
//   - Redirect URIs may be http://localhost for local apps, as Singpass
//     staging allows.
//
// Test users are Personas: fictitious people and a company, with Myinfo data
// in the real envelope shape (see DefaultPersonas). Logins are approved
// automatically, or — with Config.Interactive — through a sign-in page listing
// the personas, for use from a browser.
//
// The server listens on plain HTTP on a loopback address, so the client needs
// singpass.Dependencies.AllowLoopbackHTTP, which is refused under production
// assurance.
//
// Not reproduced: acr_values, refresh tokens, and Singpass's full error
// vocabulary.
package singpasstest
