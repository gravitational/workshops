package aws

import (
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

// The console is a read-only view of the simulated account: its instances,
// what Terraform created in IAM, the SSM commands Teleport sent, and the
// most recent API calls.

var consoleTmpl = template.Must(template.New("console").Funcs(template.FuncMap{
	"ago": func(t time.Time) string { return time.Since(t).Round(time.Second).String() + " ago" },
	"tags": func(m map[string]string) string {
		var parts []string
		for _, k := range []string{"env", "team"} {
			if v, ok := m[k]; ok {
				parts = append(parts, k+"="+v)
			}
		}
		return strings.Join(parts, ", ")
	},
	"policies": func(r role) string {
		var names []string
		for _, arn := range r.AttachedPolicies {
			names = append(names, arn[strings.LastIndex(arn, "/")+1:])
		}
		return strings.Join(names, ", ")
	},
}).Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>AWS (simulated) · {{.Account}}</title>
<meta http-equiv="refresh" content="10">
<style>
body{font:14px/1.45 system-ui,sans-serif;margin:0;background:#f2f3f3;color:#16191f}
header{background:#232f3e;color:#fff;padding:12px 24px;display:flex;gap:16px;align-items:baseline}
header b{color:#ff9900;font-size:18px} main{padding:8px 24px 32px;max-width:1200px}
h2{font-size:16px;margin:24px 0 8px} section{background:#fff;border:1px solid #d5dbdb;border-radius:8px;padding:4px 16px 12px}
table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eaeded;vertical-align:top}
th{font-weight:600;color:#545b64} code{font-size:12px} .muted{color:#687078} .bad{color:#d13212} .ok{color:#1d8102}
</style></head><body>
<header><b>AWS</b><span>simulated account {{.Account}}</span><span class="muted">endpoint {{.URL}}</span></header>
<main>
<h2>EC2 instances</h2><section><table>
<tr><th>Instance</th><th>Name</th><th>Region</th><th>State</th><th>Tags</th><th>SSM agent</th><th>Container</th></tr>
{{range .Instances}}<tr><td><code>{{.ID}}</code></td><td>{{.Name}}</td><td>{{.Region}}</td><td>{{.State}}</td><td>{{tags .Tags}}</td><td>{{.Ping}} · {{.SSMPlatformName}} {{.SSMPlatformVer}}</td><td>{{if .Container}}<code>{{.Container}}</code>{{else}}<span class="muted">none</span>{{end}}</td></tr>{{end}}
</table><p class="muted">SSM commands for an instance with a container run in it (docker exec). An instance without one exists only in API responses.</p></section>

<h2>IAM</h2><section><table>
<tr><th>OIDC provider</th><th>Client IDs</th><th>Created</th></tr>
{{range .Providers}}<tr><td><code>{{.ARN}}</code></td><td>{{range .ClientIDs}}{{.}} {{end}}</td><td>{{ago .Created}}</td></tr>{{else}}<tr><td colspan="3" class="muted">none — run terraform apply in terraform/aws-discovery</td></tr>{{end}}
<tr><th>Role</th><th>Attached policies</th><th>Created</th></tr>
{{range .Roles}}<tr><td><code>{{.ARN}}</code></td><td>{{policies .}}</td><td>{{ago .Created}}</td></tr>{{else}}<tr><td colspan="3" class="muted">none</td></tr>{{end}}
<tr><th>Policy</th><th>Description</th><th>Created</th></tr>
{{range .Policies}}<tr><td><code>{{.ARN}}</code></td><td>{{.Description}}</td><td>{{ago .Created}}</td></tr>{{else}}<tr><td colspan="3" class="muted">none</td></tr>{{end}}
</table></section>

<h2>SSM Run Command</h2><section><table>
<tr><th>Command</th><th>Document</th><th>Region</th><th>Instances</th><th>Sent</th></tr>
{{range .Commands}}<tr><td><code>{{.ID}}</code></td><td>{{.Document}}</td><td>{{.Region}}</td><td>{{range $id, $inv := .Invocations}}<code>{{$id}}</code> <span class="{{if eq $inv.Status "Success"}}ok{{else if eq $inv.Status "Failed"}}bad{{end}}">{{$inv.Status}}{{if ne $inv.Status "InProgress"}} (exit {{$inv.ExitCode}}){{end}}</span> {{end}}</td><td>{{ago .Requested}}</td></tr>{{else}}<tr><td colspan="5" class="muted">none yet</td></tr>{{end}}
</table></section>

<h2>Recent API calls</h2><section><table>
<tr><th>When</th><th>Call</th><th>Region</th><th>Caller</th><th>Result</th></tr>
{{range .Calls}}<tr><td>{{ago .Time}}</td><td>{{.Service}}:{{.Action}}</td><td>{{.Region}}</td><td><code>{{.Caller}}</code></td><td class="{{if eq .Result "ok"}}ok{{else}}bad{{end}}">{{.Result}}</td></tr>{{else}}<tr><td colspan="5" class="muted">none yet</td></tr>{{end}}
</table></section>
</main></body></html>`))

func (s *Server) serveConsole(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	providers, roles, policies := s.iam.snapshot()
	commands := s.ssm.recent()
	if len(commands) > 20 {
		commands = commands[:20]
	}
	calls := s.calls.recent()
	if len(calls) > 40 {
		calls = calls[:40]
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := consoleTmpl.Execute(w, map[string]any{
		"Account":   s.cfg.AccountID,
		"URL":       s.cfg.URL,
		"Instances": s.instanceViews(),
		"Providers": providers,
		"Roles":     roles,
		"Policies":  policies,
		"Commands":  commands,
		"Calls":     calls,
	}); err != nil {
		log.Printf("aws: console: %v", err)
	}
}

type instanceView struct {
	instance
	Ping string
}

func (s *Server) instanceViews() []instanceView {
	var out []instanceView
	for _, i := range s.ec2 {
		out = append(out, instanceView{i, s.ssmPing(i)})
	}
	return out
}
