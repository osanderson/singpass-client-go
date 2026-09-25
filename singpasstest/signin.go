package singpasstest

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/idfoundry/fapigo/server"
)

var signInPage = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} (test)</title>
<style>
  :root { color-scheme: light dark; --accent: #c8102e; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 30rem; margin: 3rem auto; padding: 0 1rem; }
  .banner { background: #fff4d6; color: #5c4400; border-radius: 6px; padding: .5rem .75rem; font-size: .85rem; }
  h1 { font-size: 1.4rem; margin: 1.25rem 0 .25rem; }
  p.meta { color: GrayText; font-size: .9rem; margin: 0 0 1.25rem; }
  button { display: block; width: 100%; text-align: left; font: inherit; padding: .75rem 1rem; margin: .5rem 0;
           border: 1px solid color-mix(in srgb, CanvasText 20%, transparent); border-radius: 8px; background: Canvas; color: CanvasText; cursor: pointer; }
  button:hover { border-color: var(--accent); }
  button small { display: block; color: GrayText; font-size: .8rem; }
  button.cancel { text-align: center; color: GrayText; }
</style>
</head>
<body>
<div class="banner">Test server — not the real {{.Title}}. No real accounts or personal data.</div>
<h1>Log in to {{.ClientID}}</h1>
<p class="meta">Scope: {{.Scope}}</p>
<form method="post" action="{{.Action}}">
  <input type="hidden" name="handle" value="{{.Handle}}">
  <input type="hidden" name="scope" value="{{.Scope}}">
  {{range .Personas}}
  <button name="subject" value="{{.Subject}}">{{.Name}}<small>{{.Subject}}</small></button>
  {{end}}
  <button class="cancel" name="decision" value="cancel">Cancel</button>
</form>
</body>
</html>`))

func renderSignIn(w http.ResponseWriter, s *Server, interaction server.InteractionRequired) {
	title := "Singpass"
	if s.cfg.Issuer == Corppass {
		title = "Corppass"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = signInPage.Execute(w, map[string]any{
		"Title":    title,
		"ClientID": string(interaction.Interaction.ClientID),
		"Scope":    strings.Join(interaction.Interaction.Scope, " "),
		"Handle":   interaction.Handle.String(),
		"Action":   s.endpoint("/auth/decision"),
		"Personas": s.personas,
	})
}
