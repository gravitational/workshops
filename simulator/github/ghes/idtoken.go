package ghes

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// idToken serves GitHub Actions' ID token endpoint, which a job reaches via
// ACTIONS_ID_TOKEN_REQUEST_URL (+ "&audience=…") with
// "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN". It answers
// {"value": "<jwt>"} with the run's claims.
func (a *API) idToken(w http.ResponseWriter, r *http.Request) {
	token, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, err := strconv.ParseInt(r.URL.Query().Get("run"), 10, 64)
	if err != nil || !hasBearer {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	run, ok := a.Store.RunForRequestToken(id, token)
	if !ok {
		// Tell a finished run (right token, too late) apart from a bad token.
		if prev, found := a.Store.Get(id); found && tokenMatches(&prev, token) {
			http.Error(w, "workflow run is not in progress", http.StatusForbidden)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	audience := r.URL.Query().Get("audience")
	if audience == "" {
		http.Error(w, "audience is required", http.StatusBadRequest)
		return
	}

	claims := ActionsClaims(a.Issuer.URL(), audience, RunInfo{
		Repository:   a.Repository,
		Ref:          run.Ref,
		SHA:          run.SHA,
		EventName:    eventName,
		Actor:        run.Actor,
		WorkflowName: run.WorkflowName,
		WorkflowPath: run.Workflow,
		RunID:        run.ID,
		RunNumber:    run.Number,
	}, a.now())
	jwt, err := a.Issuer.Sign(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("github: issued ID token for run %d (repo=%s, ref=%s, aud=%s)", run.ID, a.Repository, run.Ref, audience)
	writeJSON(w, map[string]string{"value": jwt})
}

// tokenMatches reports whether token is r's ID token request token. A run
// that was never claimed has no token and matches nothing.
func tokenMatches(r *Run, token string) bool {
	return r.requestToken != "" &&
		subtle.ConstantTimeCompare([]byte(r.requestToken), []byte(token)) == 1
}
