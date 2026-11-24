package ghes

import (
	"hash/fnv"
	"strconv"
	"strings"
	"time"
	"uuid"
)

// RunInfo describes the workflow run a job's ID token is minted for.
type RunInfo struct {
	Repository, Ref, SHA, EventName, Actor, WorkflowName, WorkflowPath string
	RunID                                                              int64
	RunNumber                                                          int
}

// ActionsClaims returns the claims GitHub Actions puts in a job's OIDC ID
// token (https://docs.github.com/en/actions/reference/security/oidc) for
// the given run. All values are strings except the NumericDate time claims,
// matching GitHub's format and what Teleport's github join method decodes.
// Empty-by-default claims (environment, base_ref, head_ref, enterprise*) are
// omitted, as GitHub does.
func ActionsClaims(issuerURL, audience string, r RunInfo, now time.Time) map[string]any {
	owner, _, _ := strings.Cut(r.Repository, "/")
	workflowRef := r.Repository + "/" + r.WorkflowPath + "@" + r.Ref
	return map[string]any{
		"iss": issuerURL,
		"aud": audience,
		"sub": "repo:" + r.Repository + ":ref:" + r.Ref,
		"iat": now.Unix(),
		"nbf": now.Add(-5 * time.Second).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": uuid.New().String(),

		"repository":            r.Repository,
		"repository_id":         numericID("repo", r.Repository),
		"repository_owner":      owner,
		"repository_owner_id":   numericID("owner", owner),
		"repository_visibility": "private",
		"ref":                   r.Ref,
		"ref_type":              refType(r.Ref),
		"ref_protected":         "false",
		"sha":                   r.SHA,
		"event_name":            r.EventName,
		"actor":                 r.Actor,
		"actor_id":              numericID("user", r.Actor),
		"workflow":              r.WorkflowName,
		"workflow_ref":          workflowRef,
		"workflow_sha":          r.SHA,
		"job_workflow_ref":      workflowRef,
		"job_workflow_sha":      r.SHA,
		"run_id":                strconv.FormatInt(r.RunID, 10),
		"run_number":            strconv.Itoa(r.RunNumber),
		"run_attempt":           "1",
		"runner_environment":    "self-hosted",
	}
}

func refType(ref string) string {
	switch {
	case strings.HasPrefix(ref, "refs/heads/"):
		return "branch"
	case strings.HasPrefix(ref, "refs/tags/"):
		return "tag"
	}
	return ""
}

// numericID returns a stable, GitHub-looking numeric ID for a named object,
// so that IDs survive simulator restarts and match across runs. kind keeps
// a user and an org of the same name from colliding.
func numericID(kind, name string) string {
	h := fnv.New32a()
	h.Write([]byte(kind + ":" + name))
	return strconv.FormatUint(uint64(h.Sum32()), 10)
}
