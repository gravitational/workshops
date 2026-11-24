package ghes

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Stale-run expiry: how often the store is swept, and how long a claimed run
// may go without hearing from its runner before it's failed ("runner lost").
const (
	expireInterval = 15 * time.Second
	maxRunnerIdle  = 2 * time.Minute
)

// branches are the simulated repo's branches, offered by "Run workflow".
var branches = []string{"main", "dev"}

// workflowsDir is where GitHub looks for workflows, relative to the repo root.
const workflowsDir = ".github/workflows"

// Config configures the simulated GHES.
type Config struct {
	URL        string          // GITHUB_URL, e.g. https://github.localhost:11443
	Repository string          // GITHUB_REPOSITORY, owner/name
	RepoDir    string          // GITHUB_REPO_DIR: the simulated repo's contents
	Key        *rsa.PrivateKey // Actions OIDC signing key (persisted by the caller)
}

// Server is the simulated GitHub Enterprise Server: the Actions OIDC
// issuer, ID token endpoint, runner API, workflow dispatch and web UI.
type Server struct {
	cfg   Config
	owner string
	name  string
	repo  repo
	store *Store
	api   *API
}

// New returns a server for cfg. cfg.Repository must be "owner/name".
func New(cfg Config) (*Server, error) {
	owner, name, ok := strings.Cut(cfg.Repository, "/")
	if !ok || !validRepoPart(owner) || !validRepoPart(name) {
		return nil, fmt.Errorf("repository %q must have the form owner/name, each made of letters, digits, '.', '-' and '_' (and not \".\" or \"..\")", cfg.Repository)
	}
	if cfg.Key == nil {
		return nil, errors.New("signing key is required")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	store := NewStore(time.Now)
	return &Server{
		cfg:   cfg,
		owner: owner,
		name:  name,
		repo:  repo{dir: cfg.RepoDir},
		store: store,
		api: &API{
			Store:      store,
			Issuer:     NewIssuer(cfg.Key, cfg.URL+"/_services/token"),
			Repository: cfg.Repository,
			ServerURL:  cfg.URL,
		},
	}, nil
}

// repoPart matches a GitHub owner or repository name. The repository is used
// in URL patterns and page links, so nothing else is allowed.
var repoPart = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func validRepoPart(s string) bool {
	return repoPart.MatchString(s) && s != "." && s != ".."
}

// Handler returns the server's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_services/token/.well-known/openid-configuration", s.api.Issuer.DiscoveryHandler())
	mux.HandleFunc("GET /_services/token/.well-known/jwks", s.api.Issuer.JWKSHandler())
	s.api.Register(mux)
	mux.HandleFunc("POST /"+s.cfg.Repository+"/actions/workflows/{file}/dispatches", s.dispatch)
	s.registerWeb(mux)
	return mux
}

// Run fails stale runs in the background until ctx is done.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(expireInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.store.ExpireStale(maxRunnerIdle)
		}
	}
}

// dispatch queues a run of workflow {file} on branch "ref" (the "Run
// workflow" button's form) and redirects to the run's page.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	wf, ok := s.repo.workflow(r.PathValue("file"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	branch := strings.TrimPrefix(r.PostFormValue("ref"), "refs/heads/")
	if !slices.Contains(branches, branch) {
		http.Error(w, "ref must be one of: "+strings.Join(branches, ", "), http.StatusBadRequest)
		return
	}
	if !wf.Dispatchable {
		http.Error(w, "Workflow does not have 'workflow_dispatch' trigger", http.StatusUnprocessableEntity)
		return
	}
	// A workflow that doesn't parse is still dispatched, under its path as
	// GitHub names it; the runner fails the run with the parse error.
	run := s.store.Dispatch(wf.Path, wf.Name, "refs/heads/"+branch, s.owner)
	log.Printf("github: queued run %d of %s on %s", run.ID, wf.Path, run.Ref)
	http.Redirect(w, r, s.runURL(run.ID), http.StatusSeeOther)
}
