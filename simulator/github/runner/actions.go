package runner

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultActions returns the stand-ins for the actions the demo workflow
// uses. tbot and kubectl are the paths of the preinstalled binaries.
func DefaultActions(tbot, kubectl string) map[string]Action {
	return map[string]Action{
		"actions/checkout":          checkout{},
		"azure/setup-kubectl":       setupKubectl{kubectl: kubectl},
		"teleport-actions/setup":    teleportSetup{tbot: tbot},
		"teleport-actions/auth-k8s": authK8s{tbot: tbot},
	}
}

// checkout emulates actions/checkout.
type checkout struct{}

func (checkout) Run(_ context.Context, sc *StepContext) error {
	// the runner has already copied the repository into the workspace, so do nothing
	sc.Log("Simulated actions/checkout: the runner already copied the repository into " + sc.Workspace)
	return nil
}

// setupKubectl emulates azure/setup-kubectl
type setupKubectl struct{ kubectl string }

func (a setupKubectl) Run(ctx context.Context, sc *StepContext) error {
	sc.Log("Simulated azure/setup-kubectl: using the preinstalled kubectl instead of downloading one")
	_, err := runTool(ctx, sc, sc.Env, a.kubectl, "version", "--client")
	return err
}

// teleportVersion matches `tbot version` output, as the real actions do.
var teleportVersion = regexp.MustCompile(`Teleport (?:Enterprise )?v(?P<version>[^ ]*)`)

// teleportSetup emulates teleport-actions/setup: tbot is preinstalled.
type teleportSetup struct{ tbot string }

func (a teleportSetup) Run(ctx context.Context, sc *StepContext) error {
	sc.Log("Simulated teleport-actions/setup: using the preinstalled tbot instead of downloading Teleport")
	out, err := runTool(ctx, sc, sc.Env, a.tbot, "version")
	if err != nil {
		return err
	}
	m := teleportVersion.FindStringSubmatch(out)
	if m == nil || m[1] == "" {
		return errors.New("malformed version returned by tbot")
	}
	installed := m[1]
	if want := strings.TrimSpace(sc.With["version"]); want != "" && strings.TrimPrefix(want, "v") != installed {
		sc.Log(fmt.Sprintf("Warning: requested Teleport %s, using preinstalled %s", want, installed))
	}
	return nil
}

// runTool runs name with args in the workspace, streaming its combined output
// to the step log, and returns that output.
func runTool(ctx context.Context, sc *StepContext, env []string, name string, args ...string) (string, error) {
	var out strings.Builder
	w := &lineWriter{log: func(lines ...string) {
		for _, l := range lines {
			out.WriteString(l)
			out.WriteString("\n")
		}
		sc.Log(lines...)
	}}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = sc.Workspace
	cmd.Env = env
	cmd.Stdout = w
	cmd.Stderr = w
	cmd.WaitDelay = waitDelay
	err := cmd.Run()
	w.flush()
	if ctx.Err() != nil {
		return out.String(), errors.New("The operation was canceled.")
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return out.String(), fmt.Errorf("%s exited with code %d", filepath.Base(name), exitErr.ExitCode())
	}
	return out.String(), err
}
