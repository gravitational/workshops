package ghes

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"simulator/github/api"
)

// defaultPollTimeout is how long a claim request waits for a queued run
// before answering 204 so the runner polls again.
const defaultPollTimeout = 25 * time.Second

// API serves the endpoints the runner container (/_runner/...) and the
// jobs' tbot (the Actions ID token endpoint) call.
type API struct {
	Store  *Store
	Issuer *Issuer
	// Repository is the owner/name of the simulated repository.
	Repository string
	// ServerURL is the GHES base URL, e.g. https://github.localhost:11443.
	ServerURL string
	// Now is the clock for ID token claims; time.Now if nil.
	Now func() time.Time
	// PollTimeout is how long a claim long-polls; 25s if zero.
	PollTimeout time.Duration
}

// Register mounts the API's routes on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /_runner/jobs/claim", a.claim)
	mux.HandleFunc("POST /_runner/runs/{id}/steps", runUpdate(a.Store.UpdateStep))
	mux.HandleFunc("POST /_runner/runs/{id}/logs", runUpdate(a.Store.AppendLog))
	mux.HandleFunc("POST /_runner/runs/{id}/complete", runUpdate(a.Store.Complete))
	mux.HandleFunc("GET /_services/token/idtoken", a.idToken)
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) claim(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), cmp.Or(a.PollTimeout, defaultPollTimeout))
	defer cancel()

	run, ok := a.Store.Claim(ctx)
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, api.Job{
		RunID:               run.ID,
		RunNumber:           run.Number,
		Repository:          a.Repository,
		Ref:                 run.Ref,
		SHA:                 run.SHA,
		EventName:           eventName,
		Actor:               run.Actor,
		WorkflowPath:        run.Workflow,
		ServerURL:           a.ServerURL,
		IDTokenRequestURL:   a.ServerURL + "/_services/token/idtoken?api-version=2.0&run=" + strconv.FormatInt(run.ID, 10),
		IDTokenRequestToken: run.requestToken,
	})
}

// eventName is the event that triggers every simulated run: the "Run
// workflow" button.
const eventName = "workflow_dispatch"

// runUpdate returns a handler that decodes a T from the body and applies it
// to run {id} with update.
func runUpdate[T any](update func(int64, T) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var v T
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&v); err != nil {
			http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		switch err := update(id, v); {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, ErrUnknownRun):
			http.NotFound(w, r)
		case errors.Is(err, ErrRunNotActive):
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
