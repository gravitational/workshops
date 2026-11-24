// Package runner executes GitHub Actions workflows for a simulated
// GitHub Enterprise Server.
package runner

import (
	"fmt"
	"regexp"
)

// Contexts holds the values available to `${{ … }}` expressions.
type Contexts struct {
	GitHub map[string]string // repository, ref, sha, run_id, run_number, actor, event_name, workflow, workspace, server_url, ref_name, repository_owner
	Env    map[string]string
	Steps  map[string]map[string]string // step id → outputs
}

var (
	exprRE       = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)
	githubRefRE  = regexp.MustCompile(`^github\.([A-Za-z_][A-Za-z0-9_]*)$`)
	envRefRE     = regexp.MustCompile(`^env\.([A-Za-z_][A-Za-z0-9_]*)$`)
	stepOutputRE = regexp.MustCompile(`^steps\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)$`)
)

// Expand replaces every `${{ … }}` expression in s. Only plain references of
// the form github.<key>, env.<NAME> and steps.<id>.outputs.<name> are
// supported; missing values expand to "" as on GitHub. Any other expression
// is an error containing "not supported by the simulator".
func Expand(s string, c Contexts) (string, error) {
	var err error
	out := exprRE.ReplaceAllStringFunc(s, func(match string) string {
		if err != nil {
			return ""
		}
		v, ok := lookup(exprRE.FindStringSubmatch(match)[1], c)
		if !ok {
			err = fmt.Errorf("not supported by the simulator: expression %s", match)
		}
		return v
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

// lookup resolves a single expression body. ok is false if the expression is
// not a supported reference.
func lookup(expr string, c Contexts) (value string, ok bool) {
	if m := githubRefRE.FindStringSubmatch(expr); m != nil {
		return c.GitHub[m[1]], true
	}
	if m := envRefRE.FindStringSubmatch(expr); m != nil {
		return c.Env[m[1]], true
	}
	if m := stepOutputRE.FindStringSubmatch(expr); m != nil {
		return c.Steps[m[1]][m[2]], true
	}
	return "", false
}
