package singpass

import (
	"reflect"
	"testing"
)

// check is one expectation in a table of them: got should equal want.
type check struct {
	name      string
	got, want any
}

// checkAll reports every check whose got differs from want.
func checkAll(t *testing.T, checks ...check) {
	t.Helper()
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s = %#v, want %#v", c.name, c.got, c.want)
		}
	}
}
