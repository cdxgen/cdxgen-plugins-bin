package templateinjection

import (
	"html/template"
	"net/http"
)

// Template injection: taint flows into a template.
// golem:want flow source=http-input sink=template-injection known-fail=legacy:24
func Handler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.New("x").Parse(r.FormValue("tmpl"))
	_ = tmpl.Execute(w, nil)
}
