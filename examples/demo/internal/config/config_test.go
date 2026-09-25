package config

import "testing"

// TestLoadAcrValues checks SINGPASS_ACR_VALUES reaches the Singpass apps and
// never the Corppass one, whose issuer does not understand Singpass URNs.
func TestLoadAcrValues(t *testing.T) {
	t.Setenv("SINGPASS_LOGIN_CLIENT_ID", "login-client")
	t.Setenv("MYINFO_CLIENT_ID", "myinfo-client")
	t.Setenv("MYINFO_BIZ_CLIENT_ID", "biz-client")
	t.Setenv("SINGPASS_ACR_VALUES", "urn:singpass:authentication:loa:2")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]string{
		"login": "urn:singpass:authentication:loa:2",
		"mi":    "urn:singpass:authentication:loa:2",
		"mib":   "",
	}
	if len(cfg.Apps) != len(want) {
		t.Fatalf("got %d apps, want %d", len(cfg.Apps), len(want))
	}
	for _, app := range cfg.Apps {
		if app.AcrValues != want[app.Name] {
			t.Errorf("%s AcrValues = %q, want %q", app.Name, app.AcrValues, want[app.Name])
		}
	}
}

func TestLoadAddr(t *testing.T) {
	for _, tc := range []struct {
		name, appAddr, port, want string
	}{
		{"default", "", "", ":8088"},
		{"cloud run PORT", "", "8080", ":8080"},
		{"APP_ADDR wins over PORT", "127.0.0.1:9000", "8080", "127.0.0.1:9000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SINGPASS_LOGIN_CLIENT_ID", "login-client")
			t.Setenv("APP_ADDR", tc.appAddr)
			t.Setenv("PORT", tc.port)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Addr != tc.want {
				t.Errorf("Addr = %q, want %q", cfg.Addr, tc.want)
			}
		})
	}
}
