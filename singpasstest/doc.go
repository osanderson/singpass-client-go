// Package singpasstest runs a fake Singpass or Corppass FAPI 2.0 authorization
// server in-process, so an integration can be tested — or demoed — without
// onboarding, network access or real accounts.
//
// It is a community test tool, not Singpass or Corppass: it is not affiliated
// with or endorsed by GovTech, Singpass or Corppass, holds no real accounts or
// personal data, and its sign-in page says it is a test server.
//
// It is built on FAPIgo's own authorization-server engine, so the protocol is
// genuine: pushed authorization requests with DPoP, private_key_jwt client
// authentication, PKCE, an ES256-signed id_token encrypted to the client
// (ECDH-ES+A256KW / A256CBC-HS512), and a DPoP-protected /userinfo that is
// signed and encrypted (A256GCM). On top it reproduces the Singpass/Corppass
// behaviours this library handles:
//
//   - Singpass issuers end in "/fapi"; Corppass issuers don't.
//   - authentication_context_type is required for Login clients, and it and
//     authentication_context_message are rejected for Myinfo ones; the message
//     must be at most 100 printable ASCII characters, excluding < > \ and `.
//   - Singpass omits "scope" from the token response; Corppass echoes it.
//   - Singpass /userinfo returns only the person_info items the granted scopes
//     cover.
//   - Corppass /userinfo sends each block as double-encoded JSON (and, with
//     Config.CorppassUserInfoSubClientID, Corppass's former "sub" = client_id
//     deviation, which the client refuses).
//   - id_tokens carry "sub_type" and "sub_attributes" — on Singpass released
//     per scope (user.identity, name, email, mobileno); on Corppass the entity
//     is the subject and the acting person is the "act" claim.
//   - Redirect URIs may be http://localhost for local apps, as Singpass
//     staging allows.
//   - A pushed authorization request without the openid scope is refused
//     (invalid_scope).
//
// Test users are Personas: fictitious people and a company, with Myinfo data
// in the real envelope shape (see DefaultPersonas). Logins are approved
// automatically, or — with Config.Interactive — through a sign-in page listing
// the personas, for use from a browser. The sign-in page can also log in as
// anyone else, from an NRIC or FIN and a name (and, on Corppass, a UEN):
// UserPersona and EntityPersona build the same users in code, Value and
// Coded write their Myinfo data, and LoadPersonas reads users from a JSON
// file — into which a real staging /userinfo response can be pasted.
//
// A headless test chooses the user per login instead: Server.AuthorizeAs
// with a LoginAs, or — from any HTTP client — MockPass's X-Custom-NRIC,
// X-Custom-UEN, X-Custom-UUID, X-Custom-Name and X-Custom-Error headers on
// the authorization request, which approve the login straight away even on
// an Interactive server (see HeaderNRIC).
//
// The server listens on plain HTTP on a loopback address, so the client needs
// singpass.Dependencies.AllowLoopbackHTTP, which is refused under production
// assurance. With Config.TLS it serves HTTPS instead, for a client that
// reaches it at another name.
//
// RegisterTestClients registers built-in clients with fixed, published keys
// (TestClientKeys), allowed every scope and any loopback redirect URI, so an
// app can log in without registering anything.
//
// To run the servers outside a Go test — for an app in another language, or
// by hand in a browser — use the singpass-fake-server command
// (cmd/singpass-fake-server). Config.BaseURL sets the URL clients reach a
// server at, e.g. when it runs in a container.
//
// Where a specification is stricter than Singpass, the fake follows the
// specification, so an integration that passes here doesn't depend on
// Singpass's leniency: the authorization endpoint refuses a repeated
// client_id or request_uri (RFC 6749 §3.1), and /userinfo a repeated
// Authorization header (RFC 9110 §5.3). Where Singpass departs
// from a specification on purpose, the fake does what Singpass does (the
// behaviours listed above). A rejection on a specification's account says so.
//
// Being a test tool, it explains a rejection more than Singpass does: the
// error_description adds the cause and, for the usual mistakes (an
// unregistered client or redirect URI, the wrong key, a client_assertion aud
// or DPoP htu that isn't this server's), how to fix it. Config.Logger also
// receives each rejection, and flags requests that reach the server at
// another host than its URL.
//
// Each server serves a dashboard at /_fake/ (Server.DashboardURL): its
// issuer, clients, test users and recent requests with their outcomes, also
// as JSON at /_fake/requests and from Server.Requests.
//
// Not reproduced: acr_values, refresh tokens, and Singpass's full error
// vocabulary.
package singpasstest
