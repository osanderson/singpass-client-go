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
  details { margin: .75rem 0; }
  summary { cursor: pointer; color: GrayText; }
  label { display: block; font-size: .85rem; margin: .5rem 0 .15rem; }
  input[type=text] { width: 100%; box-sizing: border-box; font: inherit; padding: .5rem; border-radius: 6px;
                     border: 1px solid color-mix(in srgb, CanvasText 25%, transparent); background: Canvas; color: CanvasText; }
  .error { color: var(--accent); font-size: .9rem; }
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
<details{{if .Error}} open{{end}}>
<summary>Log in as someone else</summary>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
  <input type="hidden" name="handle" value="{{.Handle}}">
  <input type="hidden" name="scope" value="{{.Scope}}">
  <input type="hidden" name="decision" value="custom">
  <input type="hidden" name="client_id" value="{{.ClientID}}">
  {{if .Corppass}}
  <label for="uen">Entity UEN</label><input type="text" id="uen" name="uen" required placeholder="201912345K">
  <label for="entity">Entity name</label><input type="text" id="entity" name="entity" placeholder="ACME PTE. LTD.">
  {{end}}
  <label for="nric">NRIC / FIN</label><input type="text" id="nric" name="nric" required placeholder="S1234567D">
  <label for="name">Name</label><input type="text" id="name" name="name" placeholder="TAN AH KOW">
  <button type="submit">Log in</button>
</form>
</details>
</body>
</html>`))

func renderSignIn(w http.ResponseWriter, s *Server, interaction server.InteractionRequired) {
	renderSignInPage(w, s, string(interaction.Interaction.ClientID), strings.Join(interaction.Interaction.Scope, " "), interaction.Handle.String(), "")
}

// renderSignInPage renders the sign-in page, with errMsg shown on the
// custom login form when it was rejected.
func renderSignInPage(w http.ResponseWriter, s *Server, clientID, scope, handle, errMsg string) {
	title := "Singpass"
	if s.cfg.Issuer == Corppass {
		title = "Corppass"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = signInPage.Execute(w, map[string]any{
		"Title":    title,
		"ClientID": clientID,
		"Scope":    scope,
		"Handle":   handle,
		"Action":   s.endpoint("/auth/decision"),
		"Personas": s.personas,
		"Corppass": s.cfg.Issuer == Corppass,
		"Error":    errMsg,
	})
}
