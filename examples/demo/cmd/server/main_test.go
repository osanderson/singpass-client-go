package main

import (
	"reflect"
	"testing"
)

// TestFormatAmount covers the money-formatting gate: it separates thousands only
// when the label is money-ish AND the value is a plain number (integer part ≥ 4
// digits), preserving a decimal fraction (CPF balances carry cents), and leaves
// identifiers, postal codes, years and non-money labels untouched.
func TestFormatAmount(t *testing.T) {
	cases := []struct {
		label, value, want string
	}{
		{"CPF balances › MA (MediSave)", "74584.94", "74,584.94"}, // decimal preserved
		{"CPF balances › OA (Ordinary)", "89365.6", "89,365.60"},  // 1-digit fraction padded to cents
		{"Amount", "12345", "12,345"},                             // integer (no forced .00)
		{"Revenue", "1000000", "1,000,000"},
		{"Issued amount", "500", "500"},           // < 4 int digits: unchanged
		{"Amount", "999", "999"},                  // < 4 int digits: unchanged
		{"Employment", "45000.00", "45,000.00"},   // NOA income line, keyword "employment"
		{"Date of birth", "20240101", "20240101"}, // not money-ish: unchanged
		{"UINFIN", "S1234567D", "S1234567D"},      // non-numeric: unchanged
		{"Postal", "460123", "460123"},            // not money-ish: unchanged
		{"Amount", "1234.5.6", "1234.5.6"},        // malformed: unchanged
		{"Amount", "", ""},                        // empty: unchanged
	}
	for _, c := range cases {
		if got := formatAmount(c.label, c.value); got != c.want {
			t.Errorf("formatAmount(%q, %q) = %q, want %q", c.label, c.value, got, c.want)
		}
	}
}

// TestOrderColumns checks that ranked columns float to the front in preference
// order while unranked columns keep their first-seen order behind them, and that
// an unknown key returns the columns unchanged.
func TestOrderColumns(t *testing.T) {
	// "history" ranks Month, Date, Employer, Amount.
	got := orderColumns("history", []string{"Amount", "Extra", "Month", "Date"})
	want := []string{"Month", "Date", "Amount", "Extra"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("orderColumns(history) = %v, want %v", got, want)
	}

	// Unknown key: unchanged.
	in := []string{"B", "A", "C"}
	if got := orderColumns("nope", in); !reflect.DeepEqual(got, in) {
		t.Errorf("orderColumns(nope) = %v, want %v (unchanged)", got, in)
	}
}
