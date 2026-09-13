package beliefpath

import "time"

const (
	NodeFact       = "fact"
	NodeHypothesis = "hypothesis"
	NodeIntent     = "intent"
	NodeAction     = "action"
	NodeEvidence   = "evidence"
	NodeGoal       = "goal"

	StateActive        = "active"
	StateCooling       = "cooling"
	StateSuspended     = "suspended"
	StatePrunedHard    = "pruned_hard"
	StateSolved        = "solved"
	StateBlockedPolicy = "blocked_policy"

	OutcomeProgress        = "progress"
	OutcomeNoProgress      = "no_progress"
	OutcomeNegative        = "negative_evidence"
	OutcomeInvalidArgs     = "invalid_arguments"
	OutcomeToolUnavailable = "tool_unavailable"
	OutcomeInfrastructure  = "infrastructure_error"
	OutcomePolicyBlocked   = "policy_blocked"
	OutcomeUnknown         = "unknown"
)

type ToolDescriptor struct {
	Name        string
	Description string
}

type Node struct {
	ID                    string                 `json:"id"`
	ConversationID        string                 `json:"conversation_id"`
	Kind                  string                 `json:"kind"`
	CanonicalKey          string                 `json:"canonical_key"`
	Label                 string                 `json:"label"`
	State                 string                 `json:"state"`
	Confidence            float64                `json:"confidence"`
	Prior                 float64                `json:"prior"`
	Value                 float64                `json:"value"`
	Alpha                 float64                `json:"alpha"`
	Beta                  float64                `json:"beta"`
	Visits                int64                  `json:"visits"`
	Successes             int64                  `json:"successes"`
	Failures              int64                  `json:"failures"`
	RepeatCount           int64                  `json:"repeat_count"`
	CooldownUntilRevision int64                  `json:"cooldown_until_revision"`
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

type Edge struct {
	ID             string                 `json:"id"`
	ConversationID string                 `json:"conversation_id"`
	SourceID       string                 `json:"source_id"`
	TargetID       string                 `json:"target_id"`
	Relation       string                 `json:"relation"`
	Confidence     float64                `json:"confidence"`
	Cost           float64                `json:"cost"`
	Risk           float64                `json:"risk"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type Hyperedge struct {
	ID             string                 `json:"id"`
	ConversationID string                 `json:"conversation_id"`
	Kind           string                 `json:"kind"`
	TargetID       string                 `json:"target_id"`
	MemberIDs      []string               `json:"member_ids"`
	Confidence     float64                `json:"confidence"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type Observation struct {
	ID             string                 `json:"id"`
	ConversationID string                 `json:"conversation_id"`
	MessageID      string                 `json:"message_id,omitempty"`
	SourceEventID  string                 `json:"source_event_id,omitempty"`
	RunID          string                 `json:"run_id,omitempty"`
	AgentName      string                 `json:"agent_name,omitempty"`
	ToolCallID     string                 `json:"tool_call_id,omitempty"`
	ExecutionID    string                 `json:"execution_id,omitempty"`
	ToolName       string                 `json:"tool_name,omitempty"`
	EventType      string                 `json:"event_type"`
	Outcome        string                 `json:"outcome"`
	Content        string                 `json:"content,omitempty"`
	Arguments      string                 `json:"arguments,omitempty"`
	Confidence     float64                `json:"confidence"`
	DurationMS     int64                  `json:"duration_ms,omitempty"`
	Data           map[string]interface{} `json:"data,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

type Intent struct {
	ID               string   `json:"id"`
	Key              string   `json:"key"`
	Label            string   `json:"label"`
	Objective        string   `json:"objective"`
	Phase            string   `json:"phase"`
	Prerequisites    []string `json:"prerequisites,omitempty"`
	ExpectedEvidence []string `json:"expected_evidence"`
	Capabilities     []string `json:"capabilities"`
	Prior            float64  `json:"prior"`
	State            string   `json:"state"`
	Alpha            float64  `json:"alpha"`
	Beta             float64  `json:"beta"`
	Visits           int64    `json:"visits"`
	RepeatCount      int64    `json:"repeat_count"`
	CooldownUntil    int64    `json:"cooldown_until_revision"`
}

type CandidateScore struct {
	IntentID        string  `json:"intent_id"`
	IntentKey       string  `json:"intent_key"`
	Label           string  `json:"label"`
	Score           float64 `json:"score"`
	MeanSuccess     float64 `json:"mean_success"`
	Exploration     float64 `json:"exploration"`
	InformationGain float64 `json:"information_gain"`
	Cost            float64 `json:"cost"`
	Risk            float64 `json:"risk"`
	RepeatPenalty   float64 `json:"repeat_penalty"`
	State           string  `json:"state"`
	Reason          string  `json:"reason,omitempty"`
}

type ToolScore struct {
	Name        string    `json:"name"`
	Score       float64   `json:"score"`
	Features    []float64 `json:"features,omitempty"`
	Explanation string    `json:"explanation,omitempty"`
}

type DecisionRequest struct {
	ConversationID string
	RunID          string
	AgentName      string
	Goal           string
	Tools          []ToolDescriptor
}

type Decision struct {
	ID             string           `json:"id"`
	ConversationID string           `json:"conversation_id"`
	RunID          string           `json:"run_id,omitempty"`
	AgentName      string           `json:"agent_name,omitempty"`
	GraphRevision  int64            `json:"graph_revision"`
	Mode           string           `json:"mode"`
	Variant        string           `json:"variant"`
	Intent         Intent           `json:"intent"`
	Candidates     []CandidateScore `json:"candidates"`
	ToolSlate      []ToolScore      `json:"tool_slate"`
	CreatedAt      time.Time        `json:"created_at"`
}

type GateRequest struct {
	ConversationID string
	RunID          string
	AgentName      string
	ToolCallID     string
	ToolName       string
	Arguments      string
}

type GateDecision struct {
	Allowed       bool   `json:"allowed"`
	Mode          string `json:"mode"`
	DecisionID    string `json:"decision_id,omitempty"`
	IntentID      string `json:"intent_id,omitempty"`
	GraphRevision int64  `json:"graph_revision,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type TerminalEvidence struct {
	ConversationID string
	RunID          string
	Status         string
	Verified       bool
	EvidenceRefs   []string
	FinalText      string
}

type Snapshot struct {
	ConversationID string      `json:"conversation_id"`
	Revision       int64       `json:"revision"`
	Mode           string      `json:"mode"`
	Variant        string      `json:"variant"`
	Nodes          []Node      `json:"nodes"`
	Edges          []Edge      `json:"edges"`
	Hyperedges     []Hyperedge `json:"hyperedges"`
	Decision       *Decision   `json:"decision,omitempty"`
}
