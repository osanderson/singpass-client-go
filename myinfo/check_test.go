package myinfo

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

// The Field conversions as single values, for a check: the converted value,
// or nil when the field doesn't convert.

func dateOf(f Field) any {
	if d, ok := f.Date(); ok {
		return d.Format("2006-01-02")
	}
	return nil
}

func boolOf(f Field) any {
	if b, ok := f.Bool(); ok {
		return b
	}
	return nil
}

func intOf(f Field) any {
	if n, ok := f.Int(); ok {
		return n
	}
	return nil
}

func floatOf(f Field) any {
	if x, ok := f.Float(); ok {
		return x
	}
	return nil
}
