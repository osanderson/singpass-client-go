package singpass

import (
	"testing"
	"time"
)

func TestSmallAccessors(t *testing.T) {
	own := RecommendedLimits(time.Second)
	own.HTTPTimeout = 7 * time.Second
	checkAll(t,
		check{"Staging.String()", Staging.String(), "staging"},
		check{"Production.String()", Production.String(), "production"},
		check{"DeniedError with a description", (&DeniedError{Code: "access_denied", Description: "user cancelled"}).Error(), "singpass: login denied: user cancelled (access_denied)"},
		check{"DeniedError without one", (&DeniedError{Code: "access_denied"}).Error(), "singpass: login denied: access_denied"},
		check{"resolveLimits keeps the caller's", resolveLimits(&own, time.Second).HTTPTimeout, 7 * time.Second},
		check{"resolveLimits default", resolveLimits(nil, 3*time.Second).HTTPTimeout, 3 * time.Second},
	)
}
