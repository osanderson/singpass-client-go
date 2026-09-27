package web

import singpass "github.com/osanderson/singpass-client-go"

// WithoutMyinfo is a Config.SessionIdentity that keeps the identity without
// its Myinfo / Myinfo Business data (Identity.Myinfo), so the login session
// holds the id_token claims only. Read the data in OnAuthenticated and keep
// what the app needs.
func WithoutMyinfo(id *singpass.Identity) *singpass.Identity {
	out := *id
	out.Myinfo = nil
	return &out
}

// MinimalIdentity is a Config.SessionIdentity that keeps only what identifies
// the login: the app, the subject, the granted scope, the id_token's times,
// and the id_token claims that describe the login rather than the person —
// iss, aud, sub, sub_type, acr, amr, auth_time, iat and exp. It drops the
// Myinfo data and the claims carrying personal data: sub_attributes (e.g. the
// NRIC and name) and Corppass's act (the acting person). Identity.Issuer,
// AuthMethods, AssuranceLevel and SubjectType still work on the result;
// SubjectAttributes and ActingParty are empty.
func MinimalIdentity(id *singpass.Identity) *singpass.Identity {
	out := *id
	out.Myinfo = nil
	out.Claims = make(map[string]any, len(minimalClaims))
	for _, k := range minimalClaims {
		if v, ok := id.Claims[k]; ok {
			out.Claims[k] = v
		}
	}
	return &out
}

// minimalClaims are the id_token claims MinimalIdentity keeps.
var minimalClaims = []string{"iss", "aud", "sub", "sub_type", "acr", "amr", "auth_time", "iat", "exp"}
