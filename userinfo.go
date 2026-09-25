package singpass

import (
	"github.com/idfoundry/fapigo/client"

	"github.com/osanderson/singpass-client-go/myinfo"
)

// parseMyinfo adapts FAPIgo's validated UserInfo response into the envelope-aware
// myinfo.Response view. info.AsMap presents the already-decrypted,
// inner-JWS-verified and sub-matched claims as a decoded map (it cannot fail —
// every value round-tripped through json.Unmarshal when the response was first
// parsed); myinfo.Parse then unwraps any double-encoded blocks and groups the data.
func parseMyinfo(info client.UserInfo) *myinfo.Response {
	return myinfo.Parse(info.AsMap())
}
