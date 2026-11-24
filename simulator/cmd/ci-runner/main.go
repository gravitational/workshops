// Command ci-runner is the simulated GitHub Actions runner. It long-polls
// the simulated GHES for queued workflow runs, runs each in a fresh copy of
// the repository with the workflow executor and action stand-ins, and
// reports steps, logs and the result back.
//
// Environment:
//
//	GITHUB_URL       GHES base URL (default https://github.localhost:11443)
//	GITHUB_REPO_DIR  the simulated repository's contents (default /github-repo)
//	RUNNER_WORK_DIR  where jobs run (default /tmp/runner)
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"simulator/github/api"
	"simulator/github/runner"
	"simulator/github/workflow"
)

func main() {
	baseURL := cmp.Or(os.Getenv("GITHUB_URL"), "https://github.localhost:11443")
	r := &jobRunner{
		client:  &runner.Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 60 * time.Second}},
		repoDir: cmp.Or(os.Getenv("GITHUB_REPO_DIR"), "/github-repo"),
		workDir: cmp.Or(os.Getenv("RUNNER_WORK_DIR"), "/tmp/runner"),
		actions: runner.DefaultActions("tbot", "kubectl"),
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("ci-runner: waiting for jobs from %s", baseURL)
	const minBackoff, maxBackoff = time.Second, 30 * time.Second
	backoff := minBackoff
	for ctx.Err() == nil {
		job, err := r.client.Claim(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("ci-runner: claiming a job: %v (retrying in %s)", err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = minBackoff
		if job != nil {
			r.run(ctx, job)
		}
	}
	log.Print("ci-runner: stopping")
}

type jobRunner struct {
	client  *runner.Client
	repoDir string
	workDir string
	actions map[string]runner.Action
}

// run executes job in RUNNER_WORK_DIR/<run_id>/workspace and completes it,
// then removes RUNNER_WORK_DIR/<run_id>.
func (r *jobRunner) run(ctx context.Context, job *api.Job) {
	log.Printf("ci-runner: run %d: claimed %s (#%d, %s)", job.RunID, job.WorkflowPath, job.RunNumber, job.Ref)
	runDir := filepath.Join(r.workDir, strconv.FormatInt(job.RunID, 10))
	defer func() {
		if err := os.RemoveAll(runDir); err != nil {
			log.Printf("ci-runner: run %d: cleaning up: %v", job.RunID, err)
		}
	}()

	comp, err := r.execute(ctx, job, filepath.Join(runDir, "workspace"))
	if errors.Is(err, runner.ErrRunNotInProgress) {
		log.Printf("ci-runner: run %d: abandoned: %v", job.RunID, err)
		return
	}
	if err != nil {
		comp = api.Completion{Conclusion: api.ConclusionFailure, Message: err.Error()}
	}
	// Report even if we're shutting down, so the run doesn't wait for the
	// GHES's "runner lost" expiry.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := r.client.Complete(cctx, job.RunID, comp); err != nil {
		log.Printf("ci-runner: run %d: completing: %v", job.RunID, err)
		return
	}
	if comp.Message != "" {
		log.Printf("ci-runner: run %d: %s: %s", job.RunID, comp.Conclusion, comp.Message)
	} else {
		log.Printf("ci-runner: run %d: %s", job.RunID, comp.Conclusion)
	}
}

// execute prepares workspace and runs the job's workflow in it.
// A non-nil error fails the run with the error as its message
// except [runner.ErrRunNotInProgress], which means the run must be abandoned.
func (r *jobRunner) execute(ctx context.Context, job *api.Job, workspace string) (api.Completion, error) {
	if !filepath.IsLocal(job.WorkflowPath) {
		return api.Completion{}, fmt.Errorf("invalid workflow path %q", job.WorkflowPath)
	}
	if err := os.RemoveAll(filepath.Dir(workspace)); err != nil {
		return api.Completion{}, err
	}
	if err := os.MkdirAll(filepath.Dir(workspace), 0o755); err != nil {
		return api.Completion{}, err
	}
	if err := os.CopyFS(workspace, os.DirFS(r.repoDir)); err != nil {
		return api.Completion{}, fmt.Errorf("copying the repository: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(workspace, job.WorkflowPath))
	if err != nil {
		return api.Completion{}, fmt.Errorf("reading the workflow: %w", err)
	}
	wf, err := workflow.Parse(job.WorkflowPath, data)
	if err != nil {
		return api.Completion{}, err
	}

	rep := r.client.Reporter(job.RunID)
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-rep.Inactive():
			cancel() // stop the job's processes
		case <-jobCtx.Done():
		}
	}()
	exec := &runner.Executor{Actions: r.actions, Reporter: rep}
	conclusion, err := exec.Run(jobCtx, wf, *job, workspace)
	if cerr := rep.Close(); err == nil {
		err = cerr
	}
	select {
	case <-rep.Inactive():
		return api.Completion{}, runner.ErrRunNotInProgress
	default:
	}
	if err != nil {
		return api.Completion{}, fmt.Errorf("runner error: %w", err)
	}
	return api.Completion{Conclusion: conclusion}, nil
}
