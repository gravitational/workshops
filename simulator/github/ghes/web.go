package ghes

import (
	"bytes"
	"cmp"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"simulator/github/api"
	"simulator/github/workflow"
)

//go:embed templates/*.html static/*
var webFS embed.FS

// waitingForRunner is shown while a run is queued.
const waitingForRunner = "Waiting for a runner to pick up this job…"

// pages are the web UI's templates, each parsed together with the layout.
var pages = func() map[string]*template.Template {
	funcs := template.FuncMap{"icon": icon, "ago": ago, "inc": func(i int) int { return i + 1 }}
	m := map[string]*template.Template{}
	for _, name := range []string{"code", "file", "actions", "run"} {
		m[name] = template.Must(template.New("").Funcs(funcs).ParseFS(webFS, "templates/layout.html", "templates/"+name+".html"))
	}
	return m
}()

// page is the data every page gets; Data is the page's own.
type page struct {
	Title       string
	Owner, Name string
	Repo        string // owner/name
	Tab         string // "code" or "actions"
	Data        any
}

func (s *Server) registerWeb(mux *http.ServeMux) {
	static, _ := fs.Sub(webFS, "static")
	mux.Handle("GET /_static/", http.StripPrefix("/_static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/"+s.cfg.Repository, http.StatusFound)
	})
	base := "GET /" + s.cfg.Repository
	mux.HandleFunc(base+"/{$}", s.tree)
	mux.HandleFunc(base, s.tree)
	mux.HandleFunc(base+"/tree/main/{path...}", s.tree)
	mux.HandleFunc(base+"/blob/main/{path...}", s.blob)
	mux.HandleFunc(base+"/actions", s.actions)
	mux.HandleFunc(base+"/actions/runs/{id}", s.runPage)
}

func (s *Server) render(w http.ResponseWriter, name, title, tab string, data any) {
	var buf bytes.Buffer
	p := page{Title: title, Owner: s.owner, Name: s.name, Repo: s.cfg.Repository, Tab: tab, Data: data}
	if err := pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		log.Printf("github: render %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (s *Server) treeURL(p string) string { return "/" + s.cfg.Repository + "/tree/main/" + p }
func (s *Server) blobURL(p string) string { return "/" + s.cfg.Repository + "/blob/main/" + p }
func (s *Server) runURL(id int64) string {
	return "/" + s.cfg.Repository + "/actions/runs/" + strconv.FormatInt(id, 10)
}

// crumb is one element of a path breadcrumb.
type crumb struct{ Name, Href string }

func (s *Server) crumbs(p string) []crumb {
	out := []crumb{{s.name, "/" + s.cfg.Repository}}
	if p == "" {
		return out
	}
	parts := strings.Split(p, "/")
	for i, part := range parts {
		out = append(out, crumb{part, s.treeURL(strings.Join(parts[:i+1], "/"))})
	}
	return out
}

// notFound logs unexpected lookup errors (traversal attempts are expected)
// and responds 404.
func notFound(w http.ResponseWriter, r *http.Request, err error) {
	if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errBadPath) {
		log.Printf("github: %s: %v", r.URL.Path, err)
	}
	http.NotFound(w, r)
}

type treeData struct {
	Path    string
	Crumbs  []crumb
	Parent  string // link to the parent directory; empty at the root
	Entries []entry
	Readme  string
}

// tree is the Code tab: a directory listing plus its README.md.
func (s *Server) tree(w http.ResponseWriter, r *http.Request) {
	p := strings.Trim(r.PathValue("path"), "/")
	fi, err := s.repo.stat(p)
	if err != nil {
		notFound(w, r, err)
		return
	}
	if !fi.IsDir() {
		http.Redirect(w, r, s.blobURL(p), http.StatusFound)
		return
	}
	entries, err := s.repo.list(p)
	if err != nil {
		notFound(w, r, err)
		return
	}
	d := treeData{Path: p, Crumbs: s.crumbs(p), Entries: entries}
	if p != "" {
		if parent := path.Dir(p); parent == "." {
			d.Parent = "/" + s.cfg.Repository
		} else {
			d.Parent = s.treeURL(parent)
		}
	}
	for _, e := range entries {
		if !e.Dir && e.Name == "README.md" {
			if b, err := s.repo.read(e.Path); err == nil {
				d.Readme = string(b)
			}
		}
	}
	title := s.cfg.Repository
	if p != "" {
		title = p + " · " + title
	}
	s.render(w, "code", title, "code", d)
}

type blobData struct {
	Path   string
	Crumbs []crumb
	Lines  []string
	Size   int
	Binary bool
}

// blob is the file view, with line numbers.
func (s *Server) blob(w http.ResponseWriter, r *http.Request) {
	p := strings.Trim(r.PathValue("path"), "/")
	fi, err := s.repo.stat(p)
	if err != nil {
		notFound(w, r, err)
		return
	}
	if fi.IsDir() {
		http.Redirect(w, r, s.treeURL(p), http.StatusFound)
		return
	}
	b, err := s.repo.read(p)
	if err != nil {
		notFound(w, r, err)
		return
	}
	d := blobData{Path: p, Crumbs: s.crumbs(p), Size: len(b)}
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		d.Binary = true
	} else {
		d.Lines = strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}
	s.render(w, "file", p+" · "+s.cfg.Repository, "code", d)
}

type actionsData struct {
	Workflows []workflowFile
	Selected  *workflowFile // nil for "All workflows"
	Branches  []string
	Runs      []runRow
}

type runRow struct {
	Run
	Href, Branch, State string
}

// actions is the Actions tab: workflows in the sidebar, runs on the right;
// ?workflow=<file> selects one workflow.
func (s *Server) actions(w http.ResponseWriter, r *http.Request) {
	d := actionsData{Workflows: s.repo.workflows(), Branches: branches}
	if file := r.URL.Query().Get("workflow"); file != "" {
		i := slices.IndexFunc(d.Workflows, func(wf workflowFile) bool { return wf.File == file })
		if i < 0 {
			http.NotFound(w, r)
			return
		}
		d.Selected = &d.Workflows[i]
	}
	var runs []Run
	for _, wf := range d.Workflows {
		if d.Selected == nil || d.Selected.Path == wf.Path {
			runs = append(runs, s.store.List(wf.Path)...)
		}
	}
	slices.SortFunc(runs, func(a, b Run) int { return cmp.Compare(b.ID, a.ID) })
	for _, run := range runs {
		d.Runs = append(d.Runs, runRow{
			Run:    run,
			Href:   s.runURL(run.ID),
			Branch: strings.TrimPrefix(run.Ref, "refs/heads/"),
			State:  runState(run.Status, run.Conclusion),
		})
	}
	title := "Actions · " + s.cfg.Repository
	if d.Selected != nil {
		title = d.Selected.Name + " · " + title
	}
	s.render(w, "actions", title, "actions", d)
}

// runView is a run as the run page and its JSON poll see it.
type runView struct {
	ID           int64      `json:"id"`
	Number       int        `json:"number"`
	Workflow     string     `json:"workflow"` // file name, for the back link
	WorkflowName string     `json:"workflow_name"`
	Job          string     `json:"job"`
	Branch       string     `json:"branch"`
	Actor        string     `json:"actor"`
	Status       string     `json:"status"`
	Conclusion   string     `json:"conclusion"`
	State        string     `json:"state"` // icon/style key, see runState
	StatusText   string     `json:"status_text"`
	Message      string     `json:"message"`
	Created      time.Time  `json:"created_at"`
	Steps        []stepView `json:"steps"`
}

type stepView struct {
	Name  string   `json:"name"`
	State string   `json:"state"`
	Open  bool     `json:"-"`
	Log   []string `json:"log"`
}

// runState maps a status and conclusion to one of queued, in_progress,
// success, failure, skipped.
func runState(status Status, conclusion string) string {
	switch status {
	case StatusCompleted:
		switch conclusion {
		case api.ConclusionSuccess, api.ConclusionFailure:
			return conclusion
		}
		return api.ConclusionSkipped
	case StatusInProgress:
		return api.StatusInProgress
	}
	return api.StatusQueued
}

var stateText = map[string]string{
	"queued": "Queued", "in_progress": "In progress", "success": "Success", "failure": "Failure", "skipped": "Skipped",
}

func (s *Server) runView(run Run) runView {
	v := runView{
		ID:           run.ID,
		Number:       run.Number,
		Workflow:     path.Base(run.Workflow),
		WorkflowName: run.WorkflowName,
		Job:          run.WorkflowName,
		Branch:       strings.TrimPrefix(run.Ref, "refs/heads/"),
		Actor:        run.Actor,
		Status:       string(run.Status),
		Conclusion:   run.Conclusion,
		State:        runState(run.Status, run.Conclusion),
		Message:      run.Message,
		Created:      run.Created,
		Steps:        []stepView{},
	}
	v.StatusText = stateText[v.State]
	if run.Status == StatusQueued {
		v.Message = waitingForRunner
	}
	// The job box is titled with the job's name, as on GitHub.
	if b, err := s.repo.read(run.Workflow); err == nil {
		if wf, err := workflow.Parse(run.Workflow, b); err == nil && len(wf.Jobs) == 1 {
			v.Job = cmp.Or(wf.Jobs[0].Name, wf.Jobs[0].ID)
		}
	}
	for i, st := range run.Steps {
		state := runState(Status(st.Status), st.Conclusion)
		// Steps the runner never finished (e.g. "runner lost") show as
		// skipped once the run is over.
		if run.Status == StatusCompleted && st.Status != api.StatusCompleted {
			state = api.ConclusionSkipped
		}
		v.Steps = append(v.Steps, stepView{
			Name:  cmp.Or(st.Name, fmt.Sprintf("Step %d", i+1)),
			State: state,
			Open:  state == "in_progress" || state == "failure",
			Log:   st.Log,
		})
	}
	return v
}

// runPage serves the run page, or with a ".json" suffix the run's state
// for the page's polling.
func (s *Server) runPage(w http.ResponseWriter, r *http.Request) {
	idStr, asJSON := strings.CutSuffix(r.PathValue("id"), ".json")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	run, ok := s.store.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	v := s.runView(run)
	if asJSON {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(v)
		return
	}
	s.render(w, "run", fmt.Sprintf("%s #%d · %s", v.WorkflowName, v.Number, s.cfg.Repository), "actions", struct {
		runView
		JSONURL string
		States  []string
	}{v, s.runURL(id) + ".json", []string{"queued", "in_progress", "success", "failure", "skipped"}})
}

// ago formats t relative to now, like GitHub's run list.
func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute") + " ago"
	case d < 24*time.Hour:
		return plural(int(d/time.Hour), "hour") + " ago"
	}
	return t.Format("Jan 2, 2006")
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// icons are inline SVGs (16x16) for statuses and the file browser.
var icons = map[string]string{
	"queued":      `<svg class="icon queued" viewBox="0 0 16 16" width="16" height="16"><circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="8" cy="8" r="2" fill="currentColor"/></svg>`,
	"in_progress": `<svg class="icon in_progress" viewBox="0 0 16 16" width="16" height="16"><circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-opacity=".3" stroke-width="2"/><path d="M8 2a6 6 0 0 1 6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`,
	"success":     `<svg class="icon success" viewBox="0 0 16 16" width="16" height="16"><circle cx="8" cy="8" r="7" fill="currentColor"/><path d="M4.8 8.3l2.1 2.1 4.3-4.4" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
	"failure":     `<svg class="icon failure" viewBox="0 0 16 16" width="16" height="16"><circle cx="8" cy="8" r="7" fill="currentColor"/><path d="M5.5 5.5l5 5m0-5l-5 5" stroke="#fff" stroke-width="1.6" stroke-linecap="round"/></svg>`,
	"skipped":     `<svg class="icon skipped" viewBox="0 0 16 16" width="16" height="16"><circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M4 12l8-8" stroke="currentColor" stroke-width="1.6"/></svg>`,
	"dir":         `<svg class="icon dir" viewBox="0 0 16 16" width="16" height="16"><path d="M1.5 3h4.2l1.5 1.5h7.3v8.5h-13z" fill="currentColor"/></svg>`,
	"file":        `<svg class="icon file" viewBox="0 0 16 16" width="16" height="16"><path d="M3.5 1.5h6l3 3v10h-9z" fill="none" stroke="currentColor" stroke-width="1.2"/><path d="M9.5 1.5v3h3" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>`,
	"branch":      `<svg class="icon branch" viewBox="0 0 16 16" width="16" height="16"><circle cx="4.5" cy="3.5" r="1.7" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="4.5" cy="12.5" r="1.7" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="11.5" cy="5" r="1.7" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M4.5 5.2v5.6M11.5 6.7c0 3-7 2-7 4.1" fill="none" stroke="currentColor" stroke-width="1.3"/></svg>`,
	"workflow":    `<svg class="icon workflow" viewBox="0 0 16 16" width="16" height="16"><rect x="1.5" y="1.5" width="5" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><rect x="9.5" y="9.5" width="5" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M4 6.5v3.5h5.5" fill="none" stroke="currentColor" stroke-width="1.3"/></svg>`,
	"warning":     `<svg class="icon warning" viewBox="0 0 16 16" width="16" height="16"><path d="M8 1.5l7 12.5H1z" fill="currentColor"/><path d="M8 6v4" stroke="#fff" stroke-width="1.6" stroke-linecap="round"/><circle cx="8" cy="12" r=".9" fill="#fff"/></svg>`,
}

func icon(name string) template.HTML {
	return template.HTML(icons[name]) // constant markup from the map above
}
