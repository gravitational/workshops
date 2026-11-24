package ghes

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"simulator/github/api"
)

// Status is a workflow run's status.
type Status string

const (
	StatusQueued     Status = api.StatusQueued
	StatusInProgress Status = api.StatusInProgress
	StatusCompleted  Status = api.StatusCompleted
)

// maxSteps bounds step indexes from the runner so a bad index can't make
// the store allocate without limit.
const maxSteps = 256

var (
	ErrUnknownRun   = errors.New("unknown run")
	ErrRunNotActive = errors.New("run is not in progress")
	ErrBadStepIndex = errors.New("step index out of range")
)

// Run is a workflow run. Values returned by Store are copies.
type Run struct {
	ID           int64
	Number       int
	Workflow     string // repo-relative workflow path
	WorkflowName string
	Ref, SHA     string
	Actor        string

	Status     Status
	Conclusion string
	Message    string

	Created, Started, Finished time.Time
	Steps                      []StepState

	requestToken string
	lastSeen     time.Time
}

// StepState is the state of one step of a run, as reported by the runner.
type StepState struct {
	Name       string
	Status     string
	Conclusion string
	Log        []string
}

func (r *Run) clone() *Run {
	c := *r
	c.Steps = slices.Clone(r.Steps)
	for i := range c.Steps {
		c.Steps[i].Log = slices.Clone(c.Steps[i].Log)
	}
	return &c
}

// Store holds workflow runs in memory and queues them for the runner.
type Store struct {
	now func() time.Time

	mu      sync.Mutex
	nextID  int64
	runs    map[int64]*Run
	numbers map[string]int // last run number per workflow path
	queue   []int64        // queued run IDs, oldest first
	wake    chan struct{}  // closed and replaced when a run is queued
}

// NewStore returns an empty store using now as its clock.
func NewStore(now func() time.Time) *Store {
	return &Store{
		now:     now,
		nextID:  1,
		runs:    map[int64]*Run{},
		numbers: map[string]int{},
		wake:    make(chan struct{}),
	}
}

// Dispatch queues a new run of the workflow at workflowPath.
func (s *Store) Dispatch(workflowPath, workflowName, ref, actor string) *Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextID
	s.nextID++
	s.numbers[workflowPath]++
	r := &Run{
		ID:           id,
		Number:       s.numbers[workflowPath],
		Workflow:     workflowPath,
		WorkflowName: workflowName,
		Ref:          ref,
		SHA:          fakeSHA(workflowPath, id),
		Actor:        actor,
		Status:       StatusQueued,
		Created:      s.now(),
	}
	s.runs[id] = r
	s.queue = append(s.queue, id)
	close(s.wake)
	s.wake = make(chan struct{})
	return r.clone()
}

// Claim takes the oldest queued run, marks it in progress and gives it a
// fresh ID token request token. It blocks until a run is queued or ctx is
// done, in which case it returns false.
func (s *Store) Claim(ctx context.Context) (*Run, bool) {
	for {
		s.mu.Lock()
		if len(s.queue) > 0 {
			r := s.runs[s.queue[0]]
			s.queue = s.queue[1:]
			now := s.now()
			r.Status = StatusInProgress
			r.Started = now
			r.lastSeen = now
			r.requestToken = randomToken()
			c := r.clone()
			s.mu.Unlock()
			return c, true
		}
		wake := s.wake
		s.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return nil, false
		}
	}
}

// active returns run id if it's in progress, recording that its runner
// was just heard from. s.mu must be held.
func (s *Store) active(id int64) (*Run, error) {
	r, ok := s.runs[id]
	if !ok {
		return nil, ErrUnknownRun
	}
	if r.Status != StatusInProgress {
		return nil, ErrRunNotActive
	}
	r.lastSeen = s.now()
	return r, nil
}

// step returns step i of r, adding steps as needed.
func step(r *Run, i int) (*StepState, error) {
	if i < 0 || i >= maxSteps {
		return nil, fmt.Errorf("%w: %d", ErrBadStepIndex, i)
	}
	for len(r.Steps) <= i {
		r.Steps = append(r.Steps, StepState{Status: api.StatusQueued})
	}
	return &r.Steps[i], nil
}

// UpdateStep records a step's status reported by the runner.
func (s *Store) UpdateStep(id int64, u api.StepUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.active(id)
	if err != nil {
		return err
	}
	st, err := step(r, u.Index)
	if err != nil {
		return err
	}
	if u.Name != "" {
		st.Name = u.Name
	}
	st.Status = u.Status
	st.Conclusion = u.Conclusion
	return nil
}

// AppendLog appends output lines to a step's log.
func (s *Store) AppendLog(id int64, b api.LogBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.active(id)
	if err != nil {
		return err
	}
	st, err := step(r, b.Step)
	if err != nil {
		return err
	}
	st.Log = append(st.Log, b.Lines...)
	return nil
}

// Complete finishes an in-progress run.
func (s *Store) Complete(id int64, c api.Completion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.active(id)
	if err != nil {
		return err
	}
	s.finish(r, c.Conclusion, c.Message)
	return nil
}

// finish marks r completed. s.mu must be held.
func (s *Store) finish(r *Run, conclusion, message string) {
	r.Status = StatusCompleted
	r.Conclusion = conclusion
	r.Message = message
	r.Finished = s.now()
}

// Get returns a copy of run id.
func (s *Store) Get(id int64) (Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok {
		return Run{}, false
	}
	return *r.clone(), true
}

// List returns copies of the runs of the workflow at workflowPath, newest
// first.
func (s *Store) List(workflowPath string) []Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Run
	for _, r := range s.runs {
		if r.Workflow == workflowPath {
			out = append(out, *r.clone())
		}
	}
	slices.SortFunc(out, func(a, b Run) int { return cmp.Compare(b.ID, a.ID) })
	return out
}

// RunForRequestToken returns run id if token is its ID token request token
// and the run is still in progress.
func (s *Store) RunForRequestToken(id int64, token string) (Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok || r.Status != StatusInProgress || !tokenMatches(r, token) {
		return Run{}, false
	}
	return *r.clone(), true
}

// ExpireStale fails in-progress runs whose runner hasn't been heard from
// for longer than maxIdle, so a crashed runner doesn't leave them running
// forever.
func (s *Store) ExpireStale(maxIdle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-maxIdle)
	for _, r := range s.runs {
		if r.Status == StatusInProgress && r.lastSeen.Before(cutoff) {
			s.finish(r, api.ConclusionFailure, "runner lost")
		}
	}
}

func fakeSHA(workflowPath string, id int64) string {
	sum := sha1.Sum(fmt.Appendf(nil, "%s#%d", workflowPath, id))
	return hex.EncodeToString(sum[:])
}

func randomToken() string {
	var b [32]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
