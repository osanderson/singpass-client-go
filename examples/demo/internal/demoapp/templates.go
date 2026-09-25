// Package demoapp holds the demo server's HTML rendering — the landing page with
// a login button per enabled relying party, and the signed-in profile view that
// dumps the validated id_token claims and (for Myinfo / Myinfo Business) the
// /userinfo person data. It is deliberately outside the reusable library: the
// singpass and web packages emit no HTML, handing rendering back to the caller
// through callbacks, so every embedder owns its own look.
package demoapp

import (
	"encoding/json"
	"html/template"
	"net/http"
)

// HomeApp is one relying party shown on the landing page: its slug (used to
// build the /{Name}/login link) and a human label.
type HomeApp struct {
	Name  string
	Title string
}

// ProfileData is the signed-in view: which app authenticated the user, the
// validated subject and granted scope, the pretty-printed id_token claims, and
// (for Myinfo / Myinfo Business) accessor-driven person-data sections plus the
// raw /userinfo dump.
type ProfileData struct {
	App             string
	Title           string
	Subject         string
	Scope           string
	ScopeList       []string    // Scope split into individual scope strings (chips)
	TokenHighlights []Highlight // selected id_token claims, interpreted
	ClaimsPre       string
	Blocks          string    // recognised /userinfo blocks present (e.g. "person_info")
	Sections        []Section // person data grouped by block, read via the myinfo.Response accessor
	PersonInfoPre   string    // raw /userinfo response, pretty-printed
}

// Highlight is one accessor-read field shown on the profile, demonstrating the
// envelope-aware myinfo.Response API (Label + resolved Value, with an optional Note
// such as the Myinfo source or an "unavailable" marker).
type Highlight struct {
	Label string
	Value string
	Note  string
	// NoteKind, when set, is a provenance CSS class ("gov" / "userv" / "user" /
	// "na") that colours the Note by Myinfo source. Empty for non-source notes
	// (e.g. id_token annotations), which stay the default grey.
	NoteKind string
	// Updated is the Myinfo envelope's "lastupdated" date, surfaced as a hover
	// tooltip on the row label. Empty when the item carries none.
	Updated string
	// Confidential marks a field the Myinfo envelope classifies as confidential
	// ("C"), rendered with a small lock indicator.
	Confidential bool
}

// Section is one Myinfo block (person_info, entity_info, …) rendered as a group:
// its top-level singleton leaf fields become a definition list (Rows); each nested
// singleton object (CPF balances, CPF Investment Scheme, driving licence, …)
// becomes its own sub-headed Group so the block name is not repeated on every leaf;
// and each repeated-record collection (appointments, shareholders, …) becomes a
// Table. Badge is a block-level provenance marker shown when every data-bearing
// leaf directly under the block shares one Myinfo source.
type Section struct {
	Title     string
	Anchor    string // URL-fragment slug for the block table-of-contents jump links
	Badge     string
	BadgeKind string // provenance CSS class for Badge ("gov" / "userv" / "user" / "na")
	Rows      []Highlight
	Groups    []Group
	Tables    []Table
}

// Group is a nested singleton object within a Section (e.g. "CPF balances"),
// rendered under its own sub-heading. Its leaf fields become Rows (labels relative
// to the group, so a deeper sub-object still shows a short "Account › …" path), and
// any repeated-record collection inside it (e.g. NOA history) becomes a Table.
// Badge marks a uniform Myinfo source across the group's leaves.
type Group struct {
	Title     string
	Badge     string
	BadgeKind string // provenance CSS class for Badge ("gov" / "userv" / "user" / "na")
	// Updated / Confidential are the container object's own lastupdated date and
	// confidential classification. Myinfo attaches these to the container of a
	// grouped dataset (noa-basic, drivinglicence, …) while the value leaves inside
	// carry only {value}, so they are shown once on the group heading.
	Updated      string
	Confidential bool
	Rows         []Highlight
	Tables       []Table
}

// Table renders a repeated-record collection: one column per leaf field found
// across the records (the ordered union, so heterogeneous records still line up)
// and one Row per record. Cells align to Columns by position. Badge is a
// collection-level provenance marker shown when every record shares one Myinfo
// source (each record in a Myinfo array is itself an envelope carrying its own
// source), colour-coded by BadgeKind.
type Table struct {
	Title     string
	Badge     string
	BadgeKind string // provenance CSS class for Badge ("gov" / "userv" / "user" / "na")
	Columns   []string
	Rows      []TableRow
}

// TableRow is one record; Cells align to the parent Table's Columns by index
// (an empty string where that record lacked the column's field).
type TableRow struct {
	Cells []string
}

var homeTmpl = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Singpass RP demo</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }
  h1 { font-size: 1.5rem; }
  .msg { background: #fff4e5; border: 1px solid #ffc27a; padding: .75rem 1rem; border-radius: .5rem; margin: 1rem 0; }
  ul { list-style: none; padding: 0; }
  li { margin: .5rem 0; }
  a.btn { display: inline-block; padding: .6rem 1.1rem; background: #d1350f; color: #fff; text-decoration: none; border-radius: .4rem; }
  a.btn:hover { background: #b02c0c; }
  footer { margin-top: 3rem; color: #666; font-size: .85rem; }
</style>
</head>
<body>
<h1>Singpass RP demo</h1>
{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
<p>Choose a relying party to authenticate with (Singpass / Corppass staging):</p>
<ul>
{{range .Apps}}<li><a class="btn" href="/{{.Name}}/login">Sign in with {{.Title}}</a></li>{{end}}
</ul>
<footer>FAPI 2.0 · PAR · DPoP · private_key_jwt · encrypted id_token. Staging only.</footer>
</body>
</html>`))

var profileTmpl = template.Must(template.New("profile").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} — signed in</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 60rem; margin: 3rem auto; padding: 0 1rem; color: #1a1a1a; }
  h1 { font-size: 1.4rem; }
  h2 { font-size: 1.1rem; margin: 0 0 .75rem; }
  h3 { font-size: .95rem; margin: 1.5rem 0 .4rem; }
  h3:first-of-type { margin-top: .5rem; }
  h4 { font-size: .82rem; text-transform: uppercase; letter-spacing: .03em; color: #777; margin: 1.1rem 0 .35rem; }
  h4.group { font-size: .9rem; text-transform: none; letter-spacing: 0; color: #1a1a1a; font-weight: 600; margin: 1.3rem 0 .35rem; }
  .group + dl, h4.group + dl { margin-left: .5rem; }
  .card { border: 1px solid #e5e5e5; border-radius: .6rem; padding: 1.25rem 1.5rem; margin: 1.5rem 0; }
  .card > h2 { color: #d1350f; }
  .note { color: #888; font-size: .8rem; font-weight: 400; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; margin: 0; }
  dt { font-weight: 600; }
  dd { margin: 0; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-word; }
  pre { background: #f5f5f5; border: 1px solid #ddd; border-radius: .4rem; padding: 1rem; overflow-x: auto; font-size: .8rem; }
  table { border-collapse: collapse; width: 100%; font-size: .82rem; display: block; overflow-x: auto; }
  th, td { border: 1px solid #e6e6e6; padding: .35rem .6rem; text-align: left; vertical-align: top; white-space: nowrap; }
  th { background: #faf3f1; font-weight: 600; }
  tbody tr:nth-child(even) { background: #fafafa; }
  tbody tr:hover { background: #f3eceb; }
  .lock { font-size: .75rem; cursor: help; }
  .chips { display: flex; flex-wrap: wrap; gap: .35rem; margin-top: .6rem; }
  .chip { background: #f1f1f1; border-radius: 1rem; padding: .15rem .6rem; font-size: .75rem; font-family: ui-monospace, monospace; }
  .badge { font-size: .7rem; font-weight: 500; background: #f1f1f1; color: #777; border: 1px solid #e0e0e0; border-radius: 1rem; padding: .1rem .55rem; vertical-align: middle; }
  .badge.gov { background: #eef7ee; color: #2f7d32; border-color: #cfe6cf; }
  .badge.userv { background: #e9f2fb; color: #1565a7; border-color: #c5dcf2; }
  .badge.user { background: #fdf4e3; color: #a5680a; border-color: #f0dcb0; }
  .badge.na { background: #f1f1f1; color: #777; border-color: #e0e0e0; }
  details { margin-top: 1.1rem; }
  summary { cursor: pointer; color: #666; font-size: .85rem; }
  a { color: #d1350f; }
  .btn { display: inline-block; margin-top: 1.5rem; padding: .6rem 1.1rem; background: #d1350f; color: #fff; text-decoration: none; border: 0; border-radius: .4rem; font: inherit; cursor: pointer; }
  .btn:hover { background: #b02c0c; }
  .brand { margin: 0 0 .3rem; font-size: .8rem; color: #666; }
  .legend { display: flex; flex-wrap: wrap; align-items: center; gap: .4rem; margin: .2rem 0 1.1rem; }
  .legkey { color: #555; font-size: .75rem; }
  .toc { font-size: .82rem; color: #666; margin: 0 0 1.2rem; display: flex; flex-wrap: wrap; align-items: baseline; gap: .15rem .7rem; }
  .toc a { color: #d1350f; text-decoration: none; }
  .toc a:hover { text-decoration: underline; }
  h3[id] { scroll-margin-top: 1rem; }
  footer { margin-top: 3rem; color: #666; font-size: .85rem; }
</style>
</head>
<body>
<p class="brand">Singpass RP demo</p>
<h1>Signed in via {{.Title}}</h1>
<dl>
  <dt>App</dt><dd>{{.App}}</dd>
  <dt>Subject</dt><dd><code>{{.Subject}}</code></dd>
</dl>
{{if .ScopeList}}<details><summary>Granted scope ({{len .ScopeList}})</summary>
<div class="chips">{{range .ScopeList}}<span class="chip">{{.}}</span>{{end}}</div>
</details>{{end}}

<section class="card">
<h2>id_token <span class="note">interpreted from the validated claims</span></h2>
{{if .TokenHighlights}}<dl>
{{range .TokenHighlights}}  <dt>{{.Label}}</dt><dd>{{if .Value}}<code>{{.Value}}</code>{{else}}<em style="color:#999">—</em>{{end}}{{if .Note}} <span class="note">{{.Note}}</span>{{end}}</dd>
{{end}}</dl>{{end}}
<details><summary>Raw id_token claims (JSON)</summary><pre>{{.ClaimsPre}}</pre></details>
</section>

{{if or .Sections .PersonInfoPre}}<section class="card">
<h2>Person data <span class="note">read via the myinfo.Response accessor{{if .Blocks}} · blocks: {{.Blocks}}{{end}}</span></h2>
{{if .Sections}}<div class="legend"><span class="badge gov">government-verified</span> <span class="badge userv">user-provided (verified)</span> <span class="badge user">user-provided</span> <span class="badge na">not-applicable</span> <span class="legkey"><span class="lock">🔒</span> confidential</span></div>{{end}}
{{if gt (len .Sections) 1}}<nav class="toc"><span>Jump to:</span> {{range .Sections}}<a href="#{{.Anchor}}">{{.Title}}</a>{{end}}</nav>{{end}}
{{range .Sections}}<h3 id="{{.Anchor}}">{{.Title}}{{if .Badge}} <span class="badge {{.BadgeKind}}">{{.Badge}}</span>{{end}}</h3>
{{if .Rows}}<dl>
{{range .Rows}}  <dt{{if .Updated}} title="Updated {{.Updated}}"{{end}}>{{.Label}}</dt><dd>{{if .Value}}<code>{{.Value}}</code>{{else}}<em style="color:#999">—</em>{{end}}{{if .Confidential}} <span class="lock" title="Confidential">🔒</span>{{end}}{{if .Note}} {{if .NoteKind}}<span class="badge {{.NoteKind}}"{{if .Updated}} title="Updated {{.Updated}}"{{end}}>{{.Note}}</span>{{else}}<span class="note">{{.Note}}</span>{{end}}{{end}}</dd>
{{end}}</dl>{{end}}
{{range .Groups}}<h4 class="group"{{if .Updated}} title="Updated {{.Updated}}"{{end}}>{{.Title}}{{if .Confidential}} <span class="lock" title="Confidential">🔒</span>{{end}}{{if .Badge}} <span class="badge {{.BadgeKind}}"{{if .Updated}} title="Updated {{.Updated}}"{{end}}>{{.Badge}}</span>{{end}}</h4>
{{if .Rows}}<dl>
{{range .Rows}}  <dt{{if .Updated}} title="Updated {{.Updated}}"{{end}}>{{.Label}}</dt><dd>{{if .Value}}<code>{{.Value}}</code>{{else}}<em style="color:#999">—</em>{{end}}{{if .Confidential}} <span class="lock" title="Confidential">🔒</span>{{end}}{{if .Note}} {{if .NoteKind}}<span class="badge {{.NoteKind}}"{{if .Updated}} title="Updated {{.Updated}}"{{end}}>{{.Note}}</span>{{else}}<span class="note">{{.Note}}</span>{{end}}{{end}}</dd>
{{end}}</dl>{{end}}
{{range .Tables}}<h4>{{.Title}}{{if .Badge}} <span class="badge {{.BadgeKind}}">{{.Badge}}</span>{{end}}</h4>
<table><thead><tr>{{range .Columns}}<th>{{.}}</th>{{end}}</tr></thead>
<tbody>{{range .Rows}}<tr>{{range .Cells}}<td>{{if .}}{{.}}{{else}}<span style="color:#ccc">—</span>{{end}}</td>{{end}}</tr>{{end}}</tbody></table>
{{end}}{{end}}
{{range .Tables}}<h4>{{.Title}}{{if .Badge}} <span class="badge {{.BadgeKind}}">{{.Badge}}</span>{{end}}</h4>
<table><thead><tr>{{range .Columns}}<th>{{.}}</th>{{end}}</tr></thead>
<tbody>{{range .Rows}}<tr>{{range .Cells}}<td>{{if .}}{{.}}{{else}}<span style="color:#ccc">—</span>{{end}}</td>{{end}}</tr>{{end}}</tbody></table>
{{end}}{{end}}
{{if .PersonInfoPre}}<details><summary>Raw /userinfo response (JSON)</summary><pre>{{.PersonInfoPre}}</pre></details>{{end}}
</section>{{end}}

<form method="post" action="/{{.App}}/logout"><button class="btn" type="submit">Log out</button></form>
<footer>FAPI 2.0 · PAR · DPoP · private_key_jwt · encrypted id_token. Staging only.</footer>
</body>
</html>`))

// RenderHome writes the landing page listing the enabled relying parties. message
// is an optional banner (e.g. after a denied login or an error); pass "" for none.
func RenderHome(w http.ResponseWriter, apps []HomeApp, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homeTmpl.Execute(w, struct {
		Apps    []HomeApp
		Message string
	}{Apps: apps, Message: message})
}

// RenderProfile writes the signed-in view for data.
func RenderProfile(w http.ResponseWriter, data ProfileData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = profileTmpl.Execute(w, data)
}

// PrettyJSON renders v as indented JSON for display. It returns "" for a nil map
// so the profile template can omit an empty person-info section.
func PrettyJSON(v map[string]any) string {
	if len(v) == 0 {
		return ""
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
