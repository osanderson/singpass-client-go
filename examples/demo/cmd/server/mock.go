package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/osanderson/singpass-client-go/examples/demo/internal/config"
	"github.com/osanderson/singpass-client-go/keyfile"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// startMock runs in-process fake Singpass and Corppass servers for DEMO_MOCK=1
// and points every app at them: it generates throwaway keys and registers each
// app with its fake server, exactly as onboarding would, then fills in the
// app's issuer and keys. The fakes show a persona picker in the browser.
func startMock(cfg *config.Config, logger *slog.Logger) (closeFn func(), err error) {
	// DEMO_MOCK_PERSONAS adds test users from a JSON file (see
	// singpasstest.LoadPersonas) to the built-in ones.
	personas := func(issuer singpasstest.Issuer) ([]singpasstest.Persona, error) {
		ps := singpasstest.DefaultPersonas(issuer)
		path := os.Getenv("DEMO_MOCK_PERSONAS")
		if path == "" {
			return ps, nil
		}
		extra, err := singpasstest.LoadPersonas(path, issuer)
		return append(ps, extra...), err
	}
	spPersonas, err := personas(singpasstest.Singpass)
	if err != nil {
		return nil, err
	}
	cpPersonas, err := personas(singpasstest.Corppass)
	if err != nil {
		return nil, err
	}
	singpassFake, err := singpasstest.NewServer(singpasstest.Config{Issuer: singpasstest.Singpass, Interactive: true, Personas: spPersonas})
	if err != nil {
		return nil, err
	}
	corppassFake, err := singpasstest.NewServer(singpasstest.Config{Issuer: singpasstest.Corppass, Interactive: true, Personas: cpPersonas})
	if err != nil {
		singpassFake.Close()
		return nil, err
	}
	closeFn = func() { singpassFake.Close(); corppassFake.Close() }

	for i := range cfg.Apps {
		ac := &cfg.Apps[i]
		fake, app := singpassFake, singpasstest.Myinfo
		switch ac.Name {
		case "login":
			app = singpasstest.Login
		case "mib":
			fake = corppassFake
		}
		if ac.SigKey, err = keyfile.GenerateECKey(); err != nil {
			closeFn()
			return nil, err
		}
		if ac.EncKey, err = keyfile.GenerateECKey(); err != nil {
			closeFn()
			return nil, err
		}
		ac.Issuer = fake.Issuer()
		var scopes []string
		for _, s := range ac.Scopes {
			if s != "openid" {
				scopes = append(scopes, s)
			}
		}
		if err := fake.RegisterClient(singpasstest.Client{
			ID: ac.ClientID, App: app, RedirectURIs: []string{ac.RedirectURI}, Scopes: scopes,
			SigningKey: &ac.SigKey.PublicKey, SigningKID: ac.SigKID,
			EncryptionKey: &ac.EncKey.PublicKey, EncryptionKID: ac.EncKID,
		}); err != nil {
			closeFn()
			return nil, fmt.Errorf("register %s with fake server: %w", ac.Name, err)
		}
	}
	logger.Warn("MOCK MODE: using built-in fake Singpass/Corppass servers — test personas only, not the real services",
		"singpass", singpassFake.Issuer(), "corppass", corppassFake.Issuer())
	return closeFn, nil
}
