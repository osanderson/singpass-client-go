package singpass

import (
	"time"

	"github.com/idfoundry/fapigo/client"
)

// RecommendedLimits starts from FAPIgo's conservative defaults and applies the
// three a Singpass/Corppass relying party genuinely needs to override:
//
//   - MaxIDTokenLifetime — RecommendedLimits leaves this zero on purpose (it
//     depends on the specific issuer), and client.New rejects zero. Singpass
//     stays well under 10m but Corppass Myinfo Business issues a longer-lived
//     id_token, so allow up to an hour.
//   - HTTPTimeout — the per-call bound to the authorization server.
//   - MaxJOSECompactBytes — RecommendedLimits defaults this to 16 KiB, which a
//     broad-scope Myinfo /userinfo response overshoots: requesting the full
//     person-data scope set yields an ~23 KiB response JWE (and an even larger
//     one for a person carrying many vehicle/children/CPF records), and the cap
//     bounds both the outer JWE and the decrypted inner JWS. 256 KiB gives ample
//     headroom while staying well under MaxHTTPResponseBytes (1 MiB). Only the
//     id_token and /userinfo are affected; fixed-shape artifacts (DPoP proofs,
//     client assertions) keep the library's 16 KiB default.
//
// Everything else (client-assertion lifetime, session lifetime, clock skew,
// HTTP response-size cap) takes the library's recommended value. A caller that
// needs different bounds sets Dependencies.Limits to its own client.Limits.
func RecommendedLimits(httpTimeout time.Duration) Limits {
	lim := client.RecommendedLimits()
	lim.MaxIDTokenLifetime = time.Hour
	lim.HTTPTimeout = httpTimeout
	lim.MaxJOSECompactBytes = 256 * 1024
	return lim
}
