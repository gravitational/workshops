// Package api holds the JSON wire types exchanged between the simulated
// GitHub Enterprise Server and the CI runner container.
package api

// Job is what the runner receives when it claims a queued workflow run.
type Job struct {
	RunID        int64  `json:"run_id"`
	RunNumber    int    `json:"run_number"`
	Repository   string `json:"repository"`
	Ref          string `json:"ref"`
	SHA          string `json:"sha"`
	EventName    string `json:"event_name"`
	Actor        string `json:"actor"`
	WorkflowPath string `json:"workflow_path"`
	ServerURL    string `json:"server_url"`

	// IDTokenRequestURL and IDTokenRequestToken become the job's
	// ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN. The
	// URL already has a query string, so callers append "&audience=…".
	IDTokenRequestURL   string `json:"id_token_request_url"`
	IDTokenRequestToken string `json:"id_token_request_token"`
}

// Step statuses and conclusions, as GitHub names them.
const (
	StatusQueued     = "queued"
	StatusInProgress = "in_progress"
	StatusCompleted  = "completed"

	ConclusionSuccess = "success"
	ConclusionFailure = "failure"
	ConclusionSkipped = "skipped"
)

// StepUpdate reports a step's status. Index is the step's 0-based position
// in the job; Conclusion is set once Status is completed.
type StepUpdate struct {
	Index      int    `json:"index"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion,omitempty"`
}

// LogBatch appends output lines to step Step's log.
type LogBatch struct {
	Step  int      `json:"step"`
	Lines []string `json:"lines"`
}

// Completion finishes a run. Message explains a failure, if any.
type Completion struct {
	Conclusion string `json:"conclusion"`
	Message    string `json:"message,omitempty"`
}
