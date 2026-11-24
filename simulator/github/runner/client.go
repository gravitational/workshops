package runner

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"simulator/github/api"
)

// ErrRunNotInProgress means the simulated GHES no longer accepts updates for
// a run: it was completed (e.g. expired as "runner lost") or is unknown
// (e.g. the simulator restarted). The runner should abandon the job.
var ErrRunNotInProgress = errors.New("run is no longer in progress")

// Log batching and keepalive.
var (
	flushInterval     = 250 * time.Millisecond
	maxBatchLines     = 50
	heartbeatInterval = 30 * time.Second // well inside the GHES's 2-minute idle expiry
)

// Client talks to the simulated GHES's runner API.
type Client struct {
	BaseURL string       // e.g. https://github.localhost:11443
	HTTP    *http.Client // http.DefaultClient if nil
}

func (c *Client) httpClient() *http.Client {
	return cmp.Or(c.HTTP, http.DefaultClient)
}

// Claim long-polls for a queued run. It returns nil, nil if none was queued
// before the GHES's poll timeout.
func (c *Client) Claim(ctx context.Context) (*api.Job, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/_runner/jobs/claim", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var job api.Job
		if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
			return nil, fmt.Errorf("decoding claimed job: %w", err)
		}
		return &job, nil
	default:
		return nil, fmt.Errorf("claim: %s", responseError(resp))
	}
}

// Complete finishes run runID.
func (c *Client) Complete(ctx context.Context, runID int64, comp api.Completion) error {
	return c.post(ctx, runID, "complete", comp)
}

// post sends v as JSON to /_runner/runs/{runID}/{what}, retrying network
// errors and 5xx responses a few times so a brief blip doesn't fail a job.
func (c *Client) post(ctx context.Context, runID int64, what string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	url := c.BaseURL + "/_runner/runs/" + strconv.FormatInt(runID, 10) + "/" + what
	const attempts = 4
	delay := 500 * time.Millisecond
	for attempt := 1; ; attempt++ {
		err := c.postOnce(ctx, url, body)
		var retryable *retryableError
		if err == nil || !errors.As(err, &retryable) || attempt == attempts {
			if err != nil {
				return fmt.Errorf("%s: %w", what, err)
			}
			return nil
		}
		select {
		case <-time.After(delay):
			delay *= 2
		case <-ctx.Done():
			return fmt.Errorf("%s: %w", what, err)
		}
	}
}

type retryableError struct{ err error }

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

func (c *Client) postOnce(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return &retryableError{err}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict, resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w (%s)", ErrRunNotInProgress, responseError(resp))
	case resp.StatusCode >= 500:
		return &retryableError{errors.New(responseError(resp))}
	default:
		return errors.New(responseError(resp))
	}
}

func responseError(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	msg := resp.Status
	if s := strings.TrimSpace(string(b)); s != "" {
		msg += ": " + s
	}
	return msg
}

// Reporter returns a Reporter for run runID that sends step updates
// immediately and batches log lines (sent every 250ms or 50 lines). While
// open it also sends an empty log batch every 30s of silence, so a quiet
// step doesn't look like a lost runner. Callers must Close it.
func (c *Client) Reporter(runID int64) *RunReporter {
	ctx, cancel := context.WithCancel(context.Background())
	r := &RunReporter{
		client:   c,
		runID:    runID,
		ctx:      ctx,
		cancel:   cancel,
		lastSent: time.Now(),
		inactive: make(chan struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go r.loop()
	return r
}

// RunReporter is the Reporter returned by Client.Reporter.
type RunReporter struct {
	client *Client
	runID  int64
	ctx    context.Context
	cancel context.CancelFunc

	// mu is held across requests so updates reach the GHES in call order.
	mu          sync.Mutex
	pending     []string // unsent lines of step pendingStep
	pendingStep int
	steps       int       // number of steps, from Steps
	lastSent    time.Time // of the last request, for the heartbeat
	err         error     // first error from a background flush

	inactiveOnce sync.Once
	inactive     chan struct{}
	stop, done   chan struct{}
}

var _ Reporter = (*RunReporter)(nil)

// Inactive is closed once the GHES has rejected an update because the run
// is no longer in progress (ErrRunNotInProgress).
func (r *RunReporter) Inactive() <-chan struct{} { return r.inactive }

// Steps reports the job's steps, all queued.
func (r *RunReporter) Steps(names []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.flushLocked(); err != nil {
		return err
	}
	r.steps = len(names)
	for i, name := range names {
		if err := r.sendLocked("steps", api.StepUpdate{Index: i, Name: name, Status: api.StatusQueued}); err != nil {
			return err
		}
	}
	return nil
}

// Step reports a step's status, after sending any lines it logged.
func (r *RunReporter) Step(index int, status, conclusion string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.flushLocked(); err != nil {
		return err
	}
	r.pendingStep = index
	return r.sendLocked("steps", api.StepUpdate{Index: index, Status: status, Conclusion: conclusion})
}

// Log queues lines for step index's log.
func (r *RunReporter) Log(index int, lines ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if index != r.pendingStep {
		if err := r.flushLocked(); err != nil {
			return err
		}
		r.pendingStep = index
	}
	r.pending = append(r.pending, lines...)
	for len(r.pending) >= maxBatchLines {
		if err := r.sendBatchLocked(); err != nil {
			return err
		}
	}
	return r.err
}

// Close sends any pending lines and stops the heartbeat.
func (r *RunReporter) Close() error {
	close(r.stop)
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.flushLocked()
	r.cancel()
	return err
}

func (r *RunReporter) loop() {
	defer close(r.done)
	t := time.NewTicker(min(flushInterval, heartbeatInterval))
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
		}
		r.mu.Lock()
		var err error
		switch {
		case len(r.pending) > 0:
			err = r.flushLocked()
		case r.steps > 0 && time.Since(r.lastSent) >= heartbeatInterval:
			err = r.sendLocked("logs", api.LogBatch{Step: r.pendingStep, Lines: []string{}})
		}
		if err != nil && r.err == nil {
			r.err = err
		}
		r.mu.Unlock()
	}
}

// flushLocked sends all pending lines. r.mu must be held.
func (r *RunReporter) flushLocked() error {
	for len(r.pending) > 0 {
		if err := r.sendBatchLocked(); err != nil {
			return err
		}
	}
	return r.err
}

// sendBatchLocked sends up to maxBatchLines pending lines. On failure they
// are dropped, so a dead GHES isn't retried for every line. r.mu must be held.
func (r *RunReporter) sendBatchLocked() error {
	n := min(len(r.pending), maxBatchLines)
	batch := api.LogBatch{Step: r.pendingStep, Lines: r.pending[:n:n]}
	r.pending = r.pending[n:]
	return r.sendLocked("logs", batch)
}

func (r *RunReporter) sendLocked(what string, v any) error {
	err := r.client.post(r.ctx, r.runID, what, v)
	r.lastSent = time.Now()
	if errors.Is(err, ErrRunNotInProgress) {
		r.inactiveOnce.Do(func() { close(r.inactive) })
	}
	return err
}
