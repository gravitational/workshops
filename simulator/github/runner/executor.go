package runner

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"simulator/github/api"
	"simulator/github/workflow"
)

// Reporter receives a job's progress.
type Reporter interface {
	Steps(names []string) error // full step list up front (index order)
	Step(index int, status, conclusion string) error
	Log(index int, lines ...string) error
}

// Action is a stand-in for a `uses:` action.
type Action interface {
	Run(ctx context.Context, sc *StepContext) error
}

// StepContext is what an Action gets to work with.
type StepContext struct {
	With      map[string]string // expanded
	Env       []string          // effective env for this step
	Workspace string
	Log       func(lines ...string)
	SetOutput func(name, value string)
	ExportEnv func(name, value string) // like core.exportVariable
}

// Executor runs a workflow's jobs and steps in order.
type Executor struct {
	Actions  map[string]Action // key "owner/name", version stripped
	Bash     string            // default "bash"
	Reporter Reporter
}

// waitDelay bounds how long a finished (or cancelled) `run:` step waits for
// leftover background processes to close its output.
const waitDelay = 2 * time.Second

// Run executes every job of wf in file order inside workspace. It returns the
// job conclusion (api.ConclusionSuccess or api.ConclusionFailure); a non-nil
// error means the executor itself failed (temp files, reporting).
func (e *Executor) Run(ctx context.Context, wf *workflow.Workflow, job api.Job, workspace string) (conclusion string, err error) {
	type plannedStep struct {
		job  *workflow.Job
		step workflow.Step
	}
	var plan []plannedStep
	var names []string
	for i := range wf.Jobs {
		j := &wf.Jobs[i]
		for _, s := range j.Steps {
			plan = append(plan, plannedStep{j, s})
			name := s.DisplayName()
			if len(wf.Jobs) > 1 {
				name = jobDisplayName(j) + " / " + name
			}
			names = append(names, name)
		}
	}

	r := &jobRun{executor: e, wf: wf, job: job, workspace: workspace}
	if err := e.Reporter.Steps(names); err != nil {
		return api.ConclusionFailure, err
	}
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return api.ConclusionFailure, err
	}
	r.runnerTemp, err = os.MkdirTemp(filepath.Dir(workspace), "runner-temp-")
	if err != nil {
		return api.ConclusionFailure, err
	}
	r.github = githubContext(wf, job, workspace)

	conclusion = api.ConclusionSuccess
	var current *workflow.Job
	for i, ps := range plan {
		if conclusion != api.ConclusionSuccess {
			if err := e.Reporter.Step(i, api.StatusCompleted, api.ConclusionSkipped); err != nil {
				return conclusion, err
			}
			continue
		}
		if ps.job != current {
			current = ps.job
			r.startJob(current)
		}
		if err := e.Reporter.Step(i, api.StatusInProgress, ""); err != nil {
			return api.ConclusionFailure, err
		}
		ok, err := r.runStep(ctx, i, ps.step)
		if err == nil {
			err = r.reportErr()
		}
		if err != nil {
			return api.ConclusionFailure, err
		}
		stepConclusion := api.ConclusionSuccess
		if !ok {
			stepConclusion = api.ConclusionFailure
			conclusion = api.ConclusionFailure
		}
		if err := e.Reporter.Step(i, api.StatusCompleted, stepConclusion); err != nil {
			return api.ConclusionFailure, err
		}
	}
	return conclusion, nil
}

func jobDisplayName(j *workflow.Job) string { return cmp.Or(j.Name, j.ID) }

func githubContext(wf *workflow.Workflow, job api.Job, workspace string) map[string]string {
	owner, _, _ := strings.Cut(job.Repository, "/")
	refName := job.Ref
	for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
		if s, ok := strings.CutPrefix(job.Ref, prefix); ok {
			refName = s
			break
		}
	}
	return map[string]string{
		"repository":       job.Repository,
		"repository_owner": owner,
		"ref":              job.Ref,
		"ref_name":         refName,
		"sha":              job.SHA,
		"run_id":           strconv.FormatInt(job.RunID, 10),
		"run_number":       strconv.Itoa(job.RunNumber),
		"actor":            job.Actor,
		"event_name":       job.EventName,
		"workflow":         wf.Name,
		"workspace":        workspace,
		"server_url":       job.ServerURL,
	}
}

// jobRun is the state of one Executor.Run call.
type jobRun struct {
	executor   *Executor
	wf         *workflow.Workflow
	job        api.Job
	workspace  string
	runnerTemp string
	github     map[string]string

	// Per workflow job, reset by startJob.
	wfJob    *workflow.Job
	exported map[string]string            // from $GITHUB_ENV and ExportEnv
	paths    []string                     // from $GITHUB_PATH, most recent first
	outputs  map[string]map[string]string // step id → outputs

	mu     sync.Mutex
	logErr error // first error from Reporter.Log
}

func (r *jobRun) startJob(j *workflow.Job) {
	r.wfJob = j
	r.exported = map[string]string{}
	r.paths = nil
	r.outputs = map[string]map[string]string{}
}

// log sends lines to the reporter, remembering the first failure so a
// streaming step isn't interrupted by it.
func (r *jobRun) log(index int, lines ...string) {
	if len(lines) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.executor.Reporter.Log(index, lines...); err != nil && r.logErr == nil {
		r.logErr = err
	}
}

func (r *jobRun) reportErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logErr
}

// fail logs a GitHub-style error line and reports the step as failed.
func (r *jobRun) fail(index int, msg string) (bool, error) {
	r.log(index, "Error: "+msg)
	return false, nil
}

func (r *jobRun) contexts(env map[string]string) Contexts {
	return Contexts{GitHub: r.github, Env: env, Steps: r.outputs}
}

// envContext computes the `env` context for a step: workflow < job <
// $GITHUB_ENV exports < step, each level expanded against the levels below.
func (r *jobRun) envContext(step workflow.Step) (map[string]string, error) {
	env := map[string]string{}
	layer := func(vars map[string]string) error {
		base := maps.Clone(env)
		for k, v := range vars {
			expanded, err := Expand(v, r.contexts(base))
			if err != nil {
				return err
			}
			env[k] = expanded
		}
		return nil
	}
	if err := layer(r.wf.Env); err != nil {
		return nil, err
	}
	if err := layer(r.wfJob.Env); err != nil {
		return nil, err
	}
	maps.Copy(env, r.exported)
	if err := layer(step.Env); err != nil {
		return nil, err
	}
	return env, nil
}

func (r *jobRun) idTokenAllowed() bool {
	perms := r.wfJob.Permissions
	if !perms.Set {
		perms = r.wf.Permissions
	}
	return perms.IDTokenWrite
}

// fileCommands are a step's $GITHUB_ENV, $GITHUB_OUTPUT and $GITHUB_PATH.
type fileCommands struct {
	env, output, path string
}

func (r *jobRun) createFileCommands(index int) (fileCommands, error) {
	var fc fileCommands
	for _, f := range []struct {
		dst  *string
		name string
	}{{&fc.env, "env"}, {&fc.output, "output"}, {&fc.path, "path"}} {
		file, err := os.CreateTemp(r.runnerTemp, fmt.Sprintf("step%d_%s_", index, f.name))
		if err != nil {
			return fc, err
		}
		if err := file.Close(); err != nil {
			return fc, err
		}
		*f.dst = file.Name()
	}
	return fc, nil
}

// processEnv builds the environment a step's process sees.
func (r *jobRun) processEnv(envCtx map[string]string, fc fileCommands) []string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	g := r.github
	maps.Copy(env, map[string]string{
		"CI":                      "true",
		"GITHUB_ACTIONS":          "true",
		"GITHUB_REPOSITORY":       g["repository"],
		"GITHUB_REPOSITORY_OWNER": g["repository_owner"],
		"GITHUB_REF":              g["ref"],
		"GITHUB_REF_NAME":         g["ref_name"],
		"GITHUB_SHA":              g["sha"],
		"GITHUB_RUN_ID":           g["run_id"],
		"GITHUB_RUN_NUMBER":       g["run_number"],
		"GITHUB_ACTOR":            g["actor"],
		"GITHUB_EVENT_NAME":       g["event_name"],
		"GITHUB_WORKFLOW":         g["workflow"],
		"GITHUB_WORKSPACE":        g["workspace"],
		"GITHUB_SERVER_URL":       g["server_url"],
		"RUNNER_TEMP":             r.runnerTemp,
	})
	maps.Copy(env, envCtx)
	if len(r.paths) > 0 {
		path := strings.Join(r.paths, string(os.PathListSeparator))
		if env["PATH"] != "" {
			path += string(os.PathListSeparator) + env["PATH"]
		}
		env["PATH"] = path
	}
	env["GITHUB_ENV"] = fc.env
	env["GITHUB_OUTPUT"] = fc.output
	env["GITHUB_PATH"] = fc.path
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_URL")
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if r.idTokenAllowed() {
		env["ACTIONS_ID_TOKEN_REQUEST_URL"] = r.job.IDTokenRequestURL
		env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = r.job.IDTokenRequestToken
	}
	out := make([]string, 0, len(env))
	for _, k := range slices.Sorted(maps.Keys(env)) {
		out = append(out, k+"="+env[k])
	}
	return out
}

// runStep runs one step. ok reports whether the step succeeded; err is an
// executor-internal failure.
func (r *jobRun) runStep(ctx context.Context, index int, step workflow.Step) (ok bool, err error) {
	envCtx, err := r.envContext(step)
	if err != nil {
		return r.fail(index, err.Error())
	}
	fc, err := r.createFileCommands(index)
	if err != nil {
		return false, err
	}
	env := r.processEnv(envCtx, fc)
	exprs := r.contexts(envCtx)

	outputs := map[string]string{}
	if step.Run != "" {
		ok, err = r.runScript(ctx, index, step, exprs, env)
	} else {
		ok, err = r.runAction(ctx, index, step, exprs, env, outputs)
	}
	if err != nil {
		return false, err
	}
	if !r.applyFileCommands(index, step, fc, outputs) {
		ok = false
	}
	return ok, nil
}

func (r *jobRun) runScript(ctx context.Context, index int, step workflow.Step, exprs Contexts, env []string) (bool, error) {
	script, err := Expand(step.Run, exprs)
	if err != nil {
		return r.fail(index, err.Error())
	}
	f, err := os.CreateTemp(r.runnerTemp, fmt.Sprintf("step%d_*.sh", index))
	if err != nil {
		return false, err
	}
	_, werr := f.WriteString(script)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return false, werr
	}

	bash := r.executor.Bash
	if bash == "" {
		bash = "bash"
	}
	out := &lineWriter{log: func(lines ...string) { r.log(index, lines...) }}
	cmd := exec.CommandContext(ctx, bash, "--noprofile", "--norc", "-eo", "pipefail", f.Name())
	cmd.Dir = r.workspace
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Kill the whole process group so background children die too.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = waitDelay
	err = cmd.Run()
	out.flush()

	if ctx.Err() != nil {
		return r.fail(index, "The operation was canceled.")
	}
	ps := cmd.ProcessState
	if ps == nil {
		return r.fail(index, err.Error()) // failed to start, e.g. bash not found
	}
	if ps.Success() {
		// A nil err, or exec.ErrWaitDelay because a background process kept
		// the output open; either way the script itself succeeded.
		return true, nil
	}
	code := ps.ExitCode()
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		code = 128 + int(ws.Signal())
	}
	return r.fail(index, fmt.Sprintf("Process completed with exit code %d.", code))
}

func (r *jobRun) runAction(ctx context.Context, index int, step workflow.Step, exprs Contexts, env []string, outputs map[string]string) (bool, error) {
	name, _, _ := strings.Cut(step.Uses, "@")
	action, ok := r.executor.Actions[name]
	if !ok {
		return r.fail(index, "not supported by the simulator: action "+step.Uses)
	}
	with := make(map[string]string, len(step.With))
	for k, v := range step.With {
		expanded, err := Expand(v, exprs)
		if err != nil {
			return r.fail(index, err.Error())
		}
		with[k] = expanded
	}
	var mu sync.Mutex
	sc := &StepContext{
		With:      with,
		Env:       env,
		Workspace: r.workspace,
		Log:       func(lines ...string) { r.log(index, lines...) },
		SetOutput: func(name, value string) {
			mu.Lock()
			defer mu.Unlock()
			outputs[name] = value
		},
		ExportEnv: func(name, value string) {
			mu.Lock()
			defer mu.Unlock()
			r.exported[name] = value
		},
	}
	if err := action.Run(ctx, sc); err != nil {
		return r.fail(index, err.Error())
	}
	return true, nil
}

// applyFileCommands reads the step's $GITHUB_ENV, $GITHUB_OUTPUT and
// $GITHUB_PATH and applies them to later steps. outputs holds outputs already
// set by an action and is merged with the file's. It returns false (having
// logged why) if a file is malformed.
func (r *jobRun) applyFileCommands(index int, step workflow.Step, fc fileCommands, outputs map[string]string) bool {
	envData, err1 := os.ReadFile(fc.env)
	outData, err2 := os.ReadFile(fc.output)
	pathData, err3 := os.ReadFile(fc.path)
	if err := errors.Join(err1, err2, err3); err != nil {
		r.fail(index, err.Error())
		return false
	}
	exports, err := ParseEnvFile(envData)
	if err != nil {
		r.fail(index, "GITHUB_ENV: "+err.Error())
		return false
	}
	fileOutputs, err := ParseEnvFile(outData)
	if err != nil {
		r.fail(index, "GITHUB_OUTPUT: "+err.Error())
		return false
	}
	maps.Copy(r.exported, exports)
	maps.Copy(outputs, fileOutputs)
	if step.ID != "" {
		r.outputs[step.ID] = outputs
	}
	for _, p := range ParsePathFile(pathData) {
		r.paths = slices.Insert(slices.DeleteFunc(r.paths, func(s string) bool { return s == p }), 0, p)
	}
	return true
}

// lineWriter splits written output into lines and logs complete ones.
type lineWriter struct {
	log func(lines ...string)
	buf []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	var lines []string
	for {
		i := slices.Index(w.buf, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, strings.TrimSuffix(string(w.buf[:i]), "\r"))
		w.buf = w.buf[i+1:]
	}
	w.log(lines...)
	return len(p), nil
}

// flush logs any trailing partial line.
func (w *lineWriter) flush() {
	if len(w.buf) > 0 {
		w.log(strings.TrimSuffix(string(w.buf), "\r"))
		w.buf = nil
	}
}
