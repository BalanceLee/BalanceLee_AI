package beliefpath

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Service struct {
	cfg    Config
	cfgMu  sync.RWMutex
	store  *store
	logger *zap.Logger
	locks  sync.Map
}

type serviceContextKey struct{}
type runIDContextKey struct{}

func WithService(ctx context.Context, service *Service) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if service == nil {
		return ctx
	}
	return context.WithValue(ctx, serviceContextKey{}, service)
}

func FromContext(ctx context.Context) *Service {
	if ctx == nil {
		return nil
	}
	service, _ := ctx.Value(serviceContextKey{}).(*Service)
	return service
}

func WithRunID(ctx context.Context, runID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return ctx
	}
	return context.WithValue(ctx, runIDContextKey{}, runID)
}

func RunIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	runID, _ := ctx.Value(runIDContextKey{}).(string)
	return strings.TrimSpace(runID)
}

func NewService(db *sql.DB, cfg Config, logger *zap.Logger) (*Service, error) {
	cfg = cfg.Effective()
	service := &Service{
		cfg:    cfg,
		store:  newStore(db),
		logger: logger,
	}
	if !cfg.Active() {
		return service, nil
	}
	if err := service.store.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	return service, nil
}

func (s *Service) Config() Config {
	if s == nil {
		return Config{}.Effective()
	}
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

func (s *Service) Active() bool {
	return s != nil && s.store != nil && s.store.db != nil && s.Config().Active()
}

func (s *Service) Enforces() bool {
	return s != nil && s.Active() && s.Config().Enforces()
}

func (s *Service) Advises() bool {
	return s != nil && s.Active() && s.Config().Advises()
}

func (s *Service) UpdateConfig(cfg Config) error {
	if s == nil {
		return nil
	}
	cfg = cfg.Effective()
	if cfg.Active() {
		if err := s.store.ensureSchema(context.Background()); err != nil {
			return err
		}
	}
	s.cfgMu.Lock()
	s.cfg = cfg
	s.cfgMu.Unlock()
	return nil
}

func (s *Service) conversationLock(conversationID string) *sync.Mutex {
	value, _ := s.locks.LoadOrStore(strings.TrimSpace(conversationID), &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (s *Service) Observe(ctx context.Context, event Event) error {
	if !s.Active() || strings.TrimSpace(event.ConversationID) == "" {
		return nil
	}
	switch strings.TrimSpace(event.EventType) {
	case "tool_call", "tool_result", "finalization_check":
	default:
		return nil
	}
	observation := NormalizeEvent(event)
	cfg := s.Config()
	lock := s.conversationLock(observation.ConversationID)
	lock.Lock()
	defer lock.Unlock()
	if err := s.store.ensureRun(
		ctx, observation.ConversationID, observation.RunID, "", cfg,
	); err != nil {
		return err
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	inserted, err := insertObservationTx(ctx, tx, observation)
	if err != nil {
		return err
	}
	if !inserted {
		return tx.Commit()
	}
	revision := int64(0)
	if observation.EventType == "tool_call" {
		revision, err = revisionTx(ctx, tx, observation.ConversationID)
	} else {
		revision, err = bumpRevisionTx(ctx, tx, observation.ConversationID)
	}
	if err != nil {
		return err
	}
	switch observation.EventType {
	case "tool_call":
		err = s.reduceToolCall(ctx, tx, observation)
	case "tool_result":
		err = s.reduceToolResult(ctx, tx, observation, revision)
	case "finalization_check":
		err = s.reduceFinalization(ctx, tx, observation)
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Service) Decide(ctx context.Context, request DecisionRequest) (*Decision, error) {
	if !s.Active() || strings.TrimSpace(request.ConversationID) == "" {
		return nil, nil
	}
	cfg := s.Config()
	decisionCtx, cancel := context.WithTimeout(ctx, cfg.DecisionTimeout())
	defer cancel()
	lock := s.conversationLock(request.ConversationID)
	lock.Lock()
	defer lock.Unlock()

	if err := s.store.ensureRun(
		decisionCtx, request.ConversationID, request.RunID, request.Goal, cfg,
	); err != nil {
		return nil, err
	}
	existing, err := s.store.loadNodes(decisionCtx, request.ConversationID, "")
	if err != nil {
		return nil, err
	}
	intents := generateIntents(request.ConversationID, request.Goal, existing, cfg.MaxIntents)
	intents = applyPrerequisitePriors(intents, existing)
	revision, err := s.store.revision(decisionCtx, request.ConversationID)
	if err != nil {
		return nil, err
	}
	intents = applyBranchLifecycle(cfg, intents, revision)

	tx, err := s.store.db.BeginTx(decisionCtx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	goalNode := Node{
		ID:             stableID("goal", request.ConversationID),
		ConversationID: request.ConversationID,
		Kind:           NodeGoal,
		CanonicalKey:   "goal:primary",
		Label:          truncateText(request.Goal, 240),
		State:          StateActive,
		Confidence:     1,
		Prior:          1,
		Alpha:          1,
		Beta:           1,
		Metadata:       map[string]interface{}{"goal": request.Goal},
	}
	if goalNode.Label == "" {
		goalNode.Label = "完成授权安全测试目标"
	}
	if err := upsertNodeTx(decisionCtx, tx, goalNode); err != nil {
		return nil, err
	}
	intentIDs := make([]string, 0, len(intents))
	existingByCanonical := make(map[string]Node, len(existing))
	for _, node := range existing {
		existingByCanonical[node.CanonicalKey] = node
	}
	for _, intent := range intents {
		intentIDs = append(intentIDs, intent.ID)
		if err := upsertNodeTx(decisionCtx, tx, nodeFromIntent(request.ConversationID, intent)); err != nil {
			return nil, err
		}
		if err := upsertEdgeTx(decisionCtx, tx, Edge{
			ConversationID: request.ConversationID,
			SourceID:       intent.ID,
			TargetID:       goalNode.ID,
			Relation:       "candidate_for",
			Confidence:     posteriorMean(intent.Alpha, intent.Beta),
			Cost:           intentCost(intent),
			Risk:           intentRisk(intent),
		}); err != nil {
			return nil, err
		}
		memberIDs := make([]string, 0, len(intent.Prerequisites))
		scope := intentScope(intent)
		for _, prerequisite := range intent.Prerequisites {
			canonicalKey := "condition:" + scope + ":" + prerequisite
			condition := Node{
				ID:             stableID("condition", request.ConversationID, scope, prerequisite),
				ConversationID: request.ConversationID,
				Kind:           NodeHypothesis,
				CanonicalKey:   canonicalKey,
				Label:          prerequisiteLabel(prerequisite),
				State:          StateActive,
				Confidence:     0.25,
				Prior:          0.25,
				Alpha:          1,
				Beta:           1,
				Metadata:       map[string]interface{}{"condition": prerequisite, "scope": scope},
			}
			if prerequisite == "target_scope" {
				condition.Kind = NodeFact
				condition.State = StateSolved
				condition.Confidence = 1
				condition.Prior = 1
				condition.Alpha = 2
			} else if persisted, ok := existingByCanonical[canonicalKey]; ok {
				condition = persisted
			}
			if err := upsertNodeTx(decisionCtx, tx, condition); err != nil {
				return nil, err
			}
			memberIDs = append(memberIDs, condition.ID)
			if err := upsertEdgeTx(decisionCtx, tx, Edge{
				ConversationID: request.ConversationID,
				SourceID:       condition.ID,
				TargetID:       intent.ID,
				Relation:       "requires",
				Confidence:     condition.Confidence,
			}); err != nil {
				return nil, err
			}
		}
		if len(memberIDs) > 0 {
			if err := upsertHyperedgeTx(decisionCtx, tx, Hyperedge{
				ConversationID: request.ConversationID,
				Kind:           "AND",
				TargetID:       intent.ID,
				MemberIDs:      memberIDs,
				Confidence:     intentPrerequisiteConfidence(intent, existingByCanonical),
				Metadata:       map[string]interface{}{"intent_key": intent.Key},
			}); err != nil {
				return nil, err
			}
		}
	}
	if len(intentIDs) > 0 {
		if err := upsertHyperedgeTx(decisionCtx, tx, Hyperedge{
			ConversationID: request.ConversationID,
			Kind:           "OR",
			TargetID:       goalNode.ID,
			MemberIDs:      intentIDs,
			Confidence:     0.5,
			Metadata:       map[string]interface{}{"goal": request.Goal},
		}); err != nil {
			return nil, err
		}
	}
	revision, err = bumpRevisionTx(decisionCtx, tx, request.ConversationID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	scores := scoreIntents(cfg, intents, revision)
	selected, ok := selectIntent(intents, scores)
	if !ok {
		return nil, errors.New("beliefpath found no feasible intent")
	}
	toolSlate, err := s.rankTools(decisionCtx, request.Goal, selected, request.Tools)
	if err != nil {
		return nil, err
	}
	decision := Decision{
		ID:             uuid.NewString(),
		ConversationID: request.ConversationID,
		RunID:          request.RunID,
		AgentName:      strings.TrimSpace(request.AgentName),
		GraphRevision:  revision,
		Mode:           cfg.Mode,
		Variant:        cfg.Variant,
		Intent:         selected,
		Candidates:     scores,
		ToolSlate:      toolSlate,
		CreatedAt:      time.Now(),
	}
	tx, err = s.store.db.BeginTx(decisionCtx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertDecisionTx(decisionCtx, tx, decision); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &decision, nil
}

func (s *Service) Gate(ctx context.Context, request GateRequest) GateDecision {
	result := GateDecision{Allowed: true, Mode: ModeOff}
	if !s.Active() || strings.TrimSpace(request.ConversationID) == "" {
		return result
	}
	cfg := s.Config()
	result.Mode = cfg.Mode
	decision, err := s.store.latestDecision(ctx, request.ConversationID, strings.TrimSpace(request.AgentName))
	if err != nil {
		s.logWarn("beliefpath gate could not load decision", err, request.ConversationID)
		result.Reason = "planner unavailable; legacy execution preserved"
		return result
	}
	if decision == nil {
		result.Reason = "no planner decision; legacy execution preserved"
		return result
	}
	result.DecisionID = decision.ID
	result.IntentID = decision.Intent.ID
	result.GraphRevision = decision.GraphRevision
	_ = s.store.bindDecisionToolCall(
		ctx, decision.ID, request.ConversationID, request.ToolCallID, request.ToolName,
	)
	if !cfg.Enforces() || isPlannerControlTool(request.ToolName) {
		return result
	}
	if len(decision.ToolSlate) == 0 {
		result.Reason = "planner produced no executable slate; legacy execution preserved"
		return result
	}
	currentRevision, err := s.store.revision(ctx, request.ConversationID)
	if err != nil {
		result.Reason = "planner revision unavailable; legacy execution preserved"
		return result
	}
	// A small revision drift is expected when Eino executes several tool calls
	// from one model response in parallel. Larger drift requires a fresh model
	// turn so stale decisions cannot keep driving the run.
	if currentRevision > decision.GraphRevision+2 {
		result.Allowed = false
		result.Reason = "planner state changed; re-evaluate the current intent before executing another tool"
		return result
	}
	for _, candidate := range decision.ToolSlate {
		if strings.EqualFold(strings.TrimSpace(candidate.Name), strings.TrimSpace(request.ToolName)) {
			return result
		}
	}
	result.Allowed = false
	result.Reason = fmt.Sprintf(
		"tool %q is outside the selected slate for intent %q",
		request.ToolName,
		decision.Intent.Label,
	)
	return result
}

func (s *Service) Finalize(ctx context.Context, evidence TerminalEvidence) error {
	if !s.Active() || strings.TrimSpace(evidence.ConversationID) == "" {
		return nil
	}
	if strings.TrimSpace(evidence.RunID) == "" {
		_ = s.store.db.QueryRowContext(ctx,
			`SELECT run_id FROM beliefpath_runs WHERE conversation_id=?`,
			evidence.ConversationID,
		).Scan(&evidence.RunID)
	}
	event := Event{
		ConversationID: evidence.ConversationID,
		MessageID:      evidence.MessageID,
		RunID:          evidence.RunID,
		SourceEventID: stableID(
			"terminal",
			evidence.ConversationID,
			evidence.RunID,
			evidence.Status,
			strings.Join(evidence.EvidenceRefs, ","),
		),
		EventType: "finalization_check",
		Message:   evidence.FinalText,
		Data: map[string]interface{}{
			"status":           evidence.Status,
			"finalized":        evidence.Verified,
			"evidenceVerified": evidence.Verified,
			"evidenceRefs":     evidence.EvidenceRefs,
			"finalText":        evidence.FinalText,
		},
	}
	return s.Observe(ctx, event)
}

func (s *Service) Snapshot(ctx context.Context, conversationID string) (*Snapshot, error) {
	if !s.Active() || strings.TrimSpace(conversationID) == "" {
		return nil, nil
	}
	return s.store.snapshot(ctx, strings.TrimSpace(conversationID))
}

func (s *Service) ResetConversation(ctx context.Context, conversationID string) error {
	if s == nil || s.store == nil || s.store.db == nil || !s.Active() {
		return nil
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return errors.New("conversation id is required")
	}
	lock := s.conversationLock(conversationID)
	lock.Lock()
	defer lock.Unlock()
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, table := range []string{
		"beliefpath_credit_events",
		"beliefpath_action_bindings",
		"beliefpath_decisions",
		"beliefpath_observations",
		"beliefpath_hyperedges",
		"beliefpath_edges",
		"beliefpath_nodes",
		"beliefpath_runs",
	} {
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM "+table+" WHERE conversation_id=?", conversationID,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Service) ResetLearning(ctx context.Context) error {
	if s == nil || s.store == nil || s.store.db == nil || !s.Active() {
		return nil
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM beliefpath_tool_stats`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM beliefpath_credit_events`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) Directive(decision *Decision) string {
	if s == nil || decision == nil || !s.Config().Advises() {
		return ""
	}
	tools := make([]string, 0, len(decision.ToolSlate))
	for _, item := range decision.ToolSlate {
		tools = append(tools, item.Name)
	}
	return strings.Join([]string{
		"[BELIEFPATH_DIRECTIVE]",
		fmt.Sprintf("graph_revision: %d", decision.GraphRevision),
		"selected_intent: " + decision.Intent.Label,
		"objective: " + decision.Intent.Objective,
		"expected_evidence: " + strings.Join(decision.Intent.ExpectedEvidence, ", "),
		"recommended_tools: " + strings.Join(tools, ", "),
		"Select a recommended tool whose schema is visible. Do not treat tool execution success as proof of goal completion.",
		"[/BELIEFPATH_DIRECTIVE]",
	}, "\n")
}

func (s *Service) reduceToolCall(ctx context.Context, tx *sql.Tx, observation Observation) error {
	callKey := observation.ToolCallID
	if callKey == "" {
		callKey = observation.ExecutionID
	}
	if callKey == "" {
		callKey = observation.SourceEventID
	}
	actionID := stableID("action", observation.ConversationID, callKey)
	signature := stableID(
		"signature",
		strings.ToLower(observation.ToolName),
		observation.Arguments,
	)
	repeatCount, _ := countObservationSignatureTx(
		ctx, tx, observation.ConversationID, observation.ToolName, observation.Arguments,
	)
	node := Node{
		ID:             actionID,
		ConversationID: observation.ConversationID,
		Kind:           NodeAction,
		CanonicalKey:   "action:" + callKey,
		Label:          fallbackString(observation.ToolName, "工具调用"),
		State:          StateActive,
		Confidence:     observation.Confidence,
		Prior:          0.5,
		Alpha:          1,
		Beta:           1,
		RepeatCount:    repeatCount,
		Metadata: map[string]interface{}{
			"tool_name":    observation.ToolName,
			"tool_call_id": observation.ToolCallID,
			"execution_id": observation.ExecutionID,
			"arguments":    observation.Arguments,
			"signature":    signature,
			"agent":        observation.AgentName,
			"source_event": observation.SourceEventID,
		},
	}
	if err := upsertNodeTx(ctx, tx, node); err != nil {
		return err
	}
	decision, _ := decisionForToolCallTx(ctx, tx, observation.ConversationID, observation.ToolCallID)
	if decision != nil && decision.Intent.ID != "" && !isPlannerControlTool(observation.ToolName) {
		return upsertEdgeTx(ctx, tx, Edge{
			ConversationID: observation.ConversationID,
			SourceID:       decision.Intent.ID,
			TargetID:       actionID,
			Relation:       "executes",
			Confidence:     1,
			Metadata: map[string]interface{}{
				"decision_id":  decision.ID,
				"tool_call_id": observation.ToolCallID,
			},
		})
	}
	return nil
}

func (s *Service) reduceToolResult(
	ctx context.Context,
	tx *sql.Tx,
	observation Observation,
	revision int64,
) error {
	callKey := observation.ToolCallID
	if callKey == "" {
		callKey = observation.ExecutionID
	}
	if callKey == "" {
		callKey = observation.SourceEventID
	}
	actionID := stableID("action", observation.ConversationID, callKey)
	actionState := StateActive
	switch observation.Outcome {
	case OutcomeProgress:
		actionState = StateSolved
	case OutcomePolicyBlocked:
		actionState = StateBlockedPolicy
	case OutcomeInfrastructure, OutcomeToolUnavailable:
		actionState = StateCooling
	case OutcomeNegative, OutcomeNoProgress:
		actionState = StateSuspended
	}
	node := Node{
		ID:             actionID,
		ConversationID: observation.ConversationID,
		Kind:           NodeAction,
		CanonicalKey:   "action:" + callKey,
		Label:          fallbackString(observation.ToolName, "工具结果"),
		State:          actionState,
		Confidence:     observation.Confidence,
		Prior:          0.5,
		Alpha:          1,
		Beta:           1,
		Metadata: map[string]interface{}{
			"tool_name":    observation.ToolName,
			"tool_call_id": observation.ToolCallID,
			"execution_id": observation.ExecutionID,
			"outcome":      observation.Outcome,
			"result":       truncateText(observation.Content, 1200),
			"agent":        observation.AgentName,
			"source_event": observation.SourceEventID,
		},
	}
	if existing, loadErr := loadNodeByCanonicalTx(
		ctx, tx, observation.ConversationID, "action:"+callKey,
	); loadErr == nil && existing != nil {
		node = *existing
		node.State = actionState
		node.Confidence = observation.Confidence
		node.Metadata = nonNilMap(node.Metadata)
		node.Metadata["tool_name"] = observation.ToolName
		node.Metadata["tool_call_id"] = observation.ToolCallID
		node.Metadata["execution_id"] = observation.ExecutionID
		node.Metadata["outcome"] = observation.Outcome
		node.Metadata["result"] = truncateText(observation.Content, 1200)
		node.Metadata["agent"] = observation.AgentName
		node.Metadata["source_event"] = observation.SourceEventID
	}
	if observation.Outcome == OutcomeProgress {
		node.Alpha++
	} else if observation.Outcome == OutcomeNegative || observation.Outcome == OutcomeNoProgress {
		node.Beta++
	}
	observation.Data = nonNilMap(observation.Data)
	observation.Data["repeatCount"] = node.RepeatCount
	if err := upsertNodeTx(ctx, tx, node); err != nil {
		return err
	}

	decision, err := decisionForToolCallTx(ctx, tx, observation.ConversationID, observation.ToolCallID)
	if err != nil {
		return err
	}
	if decision != nil && decision.Intent.ID != "" && !isPlannerControlTool(observation.ToolName) {
		if err := s.updateIntentFromOutcome(ctx, tx, decision.Intent, observation, revision); err != nil {
			return err
		}
		if err := upsertEdgeTx(ctx, tx, Edge{
			ConversationID: observation.ConversationID,
			SourceID:       decision.Intent.ID,
			TargetID:       actionID,
			Relation:       "executes",
			Confidence:     observation.Confidence,
			Cost:           normalizedDurationCost(observation.DurationMS),
			Risk:           inferredToolRisk(strings.ToLower(observation.ToolName)),
			Metadata: map[string]interface{}{
				"decision_id": decision.ID,
				"outcome":     observation.Outcome,
			},
		}); err != nil {
			return err
		}
		if err := s.updateToolRouterFromOutcome(ctx, tx, *decision, observation); err != nil {
			return err
		}
	}

	evidenceID := stableID("evidence", observation.ConversationID, observation.SourceEventID)
	if err := upsertNodeTx(ctx, tx, Node{
		ID:             evidenceID,
		ConversationID: observation.ConversationID,
		Kind:           NodeEvidence,
		CanonicalKey:   "evidence:" + observation.SourceEventID,
		Label:          outcomeLabel(observation.Outcome),
		State:          actionState,
		Confidence:     observation.Confidence,
		Prior:          0.5,
		Alpha:          1,
		Beta:           1,
		Metadata: map[string]interface{}{
			"outcome":      observation.Outcome,
			"execution_id": observation.ExecutionID,
			"tool_call_id": observation.ToolCallID,
			"content":      truncateText(observation.Content, 1200),
		},
	}); err != nil {
		return err
	}
	if err := upsertEdgeTx(ctx, tx, Edge{
		ConversationID: observation.ConversationID,
		SourceID:       actionID,
		TargetID:       evidenceID,
		Relation:       "produces",
		Confidence:     observation.Confidence,
	}); err != nil {
		return err
	}
	for _, artifact := range ExtractArtifacts(observation.Content) {
		factID := stableID("fact", observation.ConversationID, artifact.Kind, strings.ToLower(artifact.Value))
		if err := upsertNodeTx(ctx, tx, Node{
			ID:             factID,
			ConversationID: observation.ConversationID,
			Kind:           NodeFact,
			CanonicalKey:   "fact:" + artifact.Kind + ":" + strings.ToLower(artifact.Value),
			Label:          truncateText(artifact.Value, 180),
			State:          StateActive,
			Confidence:     artifact.Confidence,
			Prior:          artifact.Confidence,
			Alpha:          1 + artifact.Confidence,
			Beta:           2 - artifact.Confidence,
			Metadata:       map[string]interface{}{"artifact_kind": artifact.Kind},
		}); err != nil {
			return err
		}
		if err := upsertEdgeTx(ctx, tx, Edge{
			ConversationID: observation.ConversationID,
			SourceID:       evidenceID,
			TargetID:       factID,
			Relation:       "supports",
			Confidence:     artifact.Confidence,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) updateIntentFromOutcome(
	ctx context.Context,
	tx *sql.Tx,
	intent Intent,
	observation Observation,
	revision int64,
) error {
	cfg := s.Config()
	intent.Visits++
	switch observation.Outcome {
	case OutcomeProgress:
		intent.Alpha++
		intent.RepeatCount = 0
		if intentSatisfied(intent, observation) {
			intent.State = StateSolved
			intent.StateReason = "expected_evidence_observed"
		} else {
			intent.State = StateActive
			intent.StateReason = ""
		}
	case OutcomeNegative, OutcomeNoProgress:
		intent.Beta++
		if repeatCount := firstInt64(observation.Data, "repeatCount"); repeatCount > 1 {
			intent.RepeatCount = repeatCount
		} else if intent.RepeatCount > 0 {
			intent.RepeatCount--
		}
	case OutcomeInfrastructure, OutcomeToolUnavailable:
		intent.State = StateCooling
		intent.StateReason = observation.Outcome
		intent.CooldownUntil = revision + cfg.CooldownRevisions
	case OutcomeInvalidArgs:
		// Argument generation failure is execution credit, not evidence that
		// the selected strategic intent is wrong.
	case OutcomePolicyBlocked:
		// The concrete action is infeasible, but another tool may still satisfy
		// the same intent. Keep the intent available.
	}
	if cfg.UsesPruning() &&
		intent.RepeatCount >= int64(cfg.RepeatLimit) &&
		intent.Visits >= int64(cfg.MinEvidenceAttempts) &&
		posteriorMean(intent.Alpha, intent.Beta) < 0.35 {
		if intent.State != StateSuspended {
			intent.PruneCount++
		}
		intent.State = StateSuspended
		intent.StateReason = "repeated_no_progress"
		intent.CooldownUntil = revision + cfg.CooldownRevisions
	}
	if err := upsertNodeTx(ctx, tx, nodeFromIntent(observation.ConversationID, intent)); err != nil {
		return err
	}
	if intent.State == StateSolved {
		return satisfyDerivedConditionTx(ctx, tx, observation.ConversationID, intent, observation)
	}
	return nil
}

func intentSatisfied(intent Intent, observation Observation) bool {
	text := strings.ToLower(observation.Content)
	artifacts := ExtractArtifacts(observation.Content)
	hasArtifact := func(kind string) bool {
		for _, artifact := range artifacts {
			if artifact.Kind == kind {
				return true
			}
		}
		return false
	}
	switch intent.Phase {
	case "recon":
		return hasArtifact("host") ||
			strings.Contains(text, "open port") ||
			strings.Contains(text, "/tcp open") ||
			strings.Contains(text, "service detected")
	case "enumeration":
		return hasArtifact("url") ||
			strings.Contains(text, "endpoint") ||
			strings.Contains(text, "directory") ||
			strings.Contains(text, "parameter")
	case "validation":
		return strings.Contains(text, "confirmed") ||
			strings.Contains(text, "vulnerable") ||
			strings.Contains(text, "漏洞已确认")
	case "credential":
		return strings.Contains(text, "login successful") ||
			strings.Contains(text, "authenticated") ||
			strings.Contains(text, "session token")
	case "exploit":
		return hasArtifact("terminal_evidence") ||
			strings.Contains(text, "shell obtained") ||
			strings.Contains(text, "uid=0(") ||
			strings.Contains(text, "uid=33(")
	case "post_exploit":
		return strings.Contains(text, "privilege") ||
			strings.Contains(text, "lateral") ||
			strings.Contains(text, "uid=0(")
	default:
		return false
	}
}

func (s *Service) updateToolRouterFromOutcome(
	ctx context.Context,
	tx *sql.Tx,
	decision Decision,
	observation Observation,
) error {
	var selected *ToolScore
	for index := range decision.ToolSlate {
		if strings.EqualFold(decision.ToolSlate[index].Name, observation.ToolName) {
			selected = &decision.ToolSlate[index]
			break
		}
	}
	if selected == nil || len(selected.Features) == 0 {
		return nil
	}
	reward, informative := selectionReward(observation.Outcome)
	if !informative {
		return nil
	}
	stat, err := loadToolStatTx(ctx, tx, observation.ToolName, len(selected.Features))
	if err != nil {
		return err
	}
	stat.update(selected.Features, reward, observation.DurationMS)
	return upsertToolStatTx(ctx, tx, stat)
}

func (s *Service) reduceFinalization(ctx context.Context, tx *sql.Tx, observation Observation) error {
	verified := firstBool(observation.Data, "evidenceVerified", "evidence_verified")
	finalized := firstBool(observation.Data, "finalized")
	if !verified || !finalized {
		return nil
	}
	references := stringSliceValue(firstValue(observation.Data, "evidenceRefs", "evidence_refs"))
	verifiedReferences, vulnerabilityEvidence, err := verifyTerminalEvidenceTx(
		ctx, tx, observation.ConversationID, references, observation.Content,
	)
	if err != nil {
		return err
	}
	if len(verifiedReferences) == 0 && !vulnerabilityEvidence {
		return nil
	}
	goalID := stableID("goal", observation.ConversationID)
	nodes, err := loadNodesTx(ctx, tx, observation.ConversationID, NodeGoal)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if node.ID == goalID {
			node.State = StateSolved
			node.Confidence = 1
			node.Value = 1
			node.Alpha++
			if err := upsertNodeTx(ctx, tx, node); err != nil {
				return err
			}
			break
		}
	}
	for _, reference := range verifiedReferences {
		reference = strings.TrimSpace(strings.TrimPrefix(reference, "mcp_execution:"))
		if reference == "" {
			continue
		}
		toolName, nodeID, err := actionForExecutionTx(ctx, tx, observation.ConversationID, reference)
		if err != nil || nodeID == "" {
			continue
		}
		if action, loadErr := loadNodeByIDTx(ctx, tx, nodeID); loadErr == nil && action != nil {
			action.State = StateSolved
			action.Alpha++
			action.Value = posteriorMean(action.Alpha, action.Beta)
			if updateErr := upsertNodeTx(ctx, tx, *action); updateErr != nil {
				return updateErr
			}
			if intent, intentErr := incomingIntentTx(ctx, tx, observation.ConversationID, nodeID); intentErr == nil && intent != nil {
				intent.State = StateSolved
				intent.Alpha++
				intent.Value = posteriorMean(intent.Alpha, intent.Beta)
				if updateErr := upsertNodeTx(ctx, tx, *intent); updateErr != nil {
					return updateErr
				}
			}
		}
		evidenceJSON, _ := json.Marshal(verifiedReferences)
		if _, err := tx.ExecContext(ctx, `
INSERT INTO beliefpath_credit_events (
	id, conversation_id, run_id, node_id, tool_name, credit_type,
	reward, evidence_refs_json, created_at
) VALUES (?, ?, ?, ?, ?, 'terminal', 1, ?, ?)`,
			uuid.NewString(), observation.ConversationID, observation.RunID,
			nodeID, toolName, string(evidenceJSON), time.Now().UnixMilli()); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE beliefpath_runs SET status='solved', updated_at=? WHERE conversation_id=?`,
		time.Now().UnixMilli(), observation.ConversationID)
	return err
}

func verifyTerminalEvidenceTx(
	ctx context.Context,
	tx *sql.Tx,
	conversationID string,
	references []string,
	finalText string,
) ([]string, bool, error) {
	verified := make([]string, 0, len(references))
	finalTerms := flagPattern.FindAllString(finalText, -1)
	var goal string
	_ = tx.QueryRowContext(ctx,
		`SELECT goal FROM beliefpath_runs WHERE conversation_id=?`,
		conversationID,
	).Scan(&goal)
	observationalGoal := !requiresExploitProof(goal)
	for _, rawReference := range references {
		reference := strings.TrimSpace(strings.TrimPrefix(rawReference, "mcp_execution:"))
		if reference == "" {
			continue
		}
		var status, resultJSON, toolName string
		err := tx.QueryRowContext(ctx, `SELECT status, COALESCE(result,''), tool_name
FROM tool_executions WHERE id=? AND conversation_id=?`,
			reference, conversationID).Scan(&status, &resultJSON, &toolName)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		if strings.ToLower(strings.TrimSpace(status)) != "completed" {
			continue
		}
		resultText := flattenJSONText(resultJSON)
		strong := successPattern.MatchString(resultText)
		for _, term := range finalTerms {
			if strings.Contains(strings.ToLower(resultText), strings.ToLower(term)) {
				strong = true
				break
			}
		}
		if strings.EqualFold(strings.TrimSpace(toolName), "record_vulnerability") &&
			!noResultPattern.MatchString(resultText) {
			strong = true
		}
		if observationalGoal && strings.TrimSpace(resultText) != "" {
			strong = true
		}
		if strong {
			verified = append(verified, "mcp_execution:"+reference)
		}
	}
	var vulnerabilityCount int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities
WHERE conversation_id=? AND LOWER(COALESCE(status,'')) NOT IN ('false_positive','rejected')`,
		conversationID).Scan(&vulnerabilityCount)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return nil, false, err
	}
	return sortStringsUnique(verified), vulnerabilityCount > 0, nil
}

func requiresExploitProof(goal string) bool {
	lower := strings.ToLower(goal)
	for _, marker := range []string{
		"flag", "getshell", "get shell", "reverse shell", "webshell",
		"rce", "root", "提权", "拿下", "获取权限", "绕过认证",
		"利用漏洞", "执行命令", "控制主机",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func flattenJSONText(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var value interface{}
	if json.Unmarshal([]byte(raw), &value) != nil {
		return raw
	}
	var parts []string
	var walk func(interface{})
	walk = func(current interface{}) {
		switch typed := current.(type) {
		case string:
			if text := strings.TrimSpace(typed); text != "" {
				parts = append(parts, text)
			}
		case []interface{}:
			for _, item := range typed {
				walk(item)
			}
		case map[string]interface{}:
			for _, key := range []string{"text", "result", "content", "error"} {
				if nested, ok := typed[key]; ok {
					walk(nested)
				}
			}
		}
	}
	walk(value)
	return strings.Join(parts, "\n")
}

func applyBranchLifecycle(cfg Config, intents []Intent, revision int64) []Intent {
	cfg = cfg.Effective()
	bestLowerBound := math.Inf(-1)
	for _, intent := range intents {
		if intent.State == StatePrunedHard || intent.State == StateBlockedPolicy ||
			intent.Visits < int64(cfg.MinEvidenceAttempts) {
			continue
		}
		lower, _ := posteriorBounds(intent.Alpha, intent.Beta)
		if lower > bestLowerBound {
			bestLowerBound = lower
		}
	}
	bestIndex := -1
	bestPrior := -1.0
	for index := range intents {
		intent := &intents[index]
		if (intent.State == StateCooling || intent.State == StateSuspended) &&
			revision >= intent.CooldownUntil {
			intent.State = StateActive
			intent.RepeatCount = 0
			intent.ReopenCount++
			intent.StateReason = "cooldown_elapsed"
		}
		if cfg.UsesPruning() &&
			intent.State == StateActive &&
			intent.Visits >= int64(cfg.MinEvidenceAttempts) &&
			!math.IsInf(bestLowerBound, -1) {
			_, upper := posteriorBounds(intent.Alpha, intent.Beta)
			if upper < bestLowerBound-cfg.SoftPruneMargin {
				intent.PruneCount++
				intent.State = StateSuspended
				intent.StateReason = "dominated_confidence_bound"
				intent.CooldownUntil = revision + cfg.CooldownRevisions
			}
		}
		if intent.State == StateActive && intent.Prior > bestPrior {
			bestPrior = intent.Prior
			bestIndex = index
		}
	}
	if bestIndex >= 0 {
		return intents
	}
	for index := range intents {
		if intents[index].State == StatePrunedHard ||
			intents[index].State == StateBlockedPolicy ||
			intents[index].State == StateSolved {
			continue
		}
		if intents[index].Prior > bestPrior {
			bestPrior = intents[index].Prior
			bestIndex = index
		}
	}
	if bestIndex >= 0 {
		intents[bestIndex].State = StateActive
		intents[bestIndex].RepeatCount = 0
		intents[bestIndex].ReopenCount++
		intents[bestIndex].StateReason = "all_alternatives_unavailable"
	}
	return intents
}

func applyPrerequisitePriors(intents []Intent, nodes []Node) []Intent {
	conditionState := make(map[string]Node, len(nodes))
	for _, node := range nodes {
		conditionState[node.CanonicalKey] = node
	}
	for index := range intents {
		intent := &intents[index]
		if len(intent.Prerequisites) == 0 {
			continue
		}
		satisfied := 0.0
		scope := intentScope(*intent)
		for _, prerequisite := range intent.Prerequisites {
			if prerequisite == "target_scope" {
				satisfied++
				continue
			}
			node, ok := conditionState["condition:"+scope+":"+prerequisite]
			if !ok {
				continue
			}
			if node.State == StateSolved {
				satisfied++
			} else {
				satisfied += clamp01(node.Confidence) * 0.5
			}
		}
		ratio := satisfied / float64(len(intent.Prerequisites))
		intent.Prior = clamp01(intent.Prior * (0.35 + 0.65*ratio))
	}
	return intents
}

func intentPrerequisiteConfidence(intent Intent, nodes map[string]Node) float64 {
	if len(intent.Prerequisites) == 0 {
		return 1
	}
	confidence := 1.0
	scope := intentScope(intent)
	for _, prerequisite := range intent.Prerequisites {
		if prerequisite == "target_scope" {
			continue
		}
		node, ok := nodes["condition:"+scope+":"+prerequisite]
		if !ok {
			confidence *= 0.25
			continue
		}
		confidence *= clamp01(node.Confidence)
	}
	return clamp01(confidence)
}

func intentScope(intent Intent) string {
	if index := strings.Index(intent.Key, ":"); index > 0 {
		return intent.Key[:index]
	}
	return "default"
}

func prerequisiteLabel(key string) string {
	switch key {
	case "target_scope":
		return "目标与授权范围已确认"
	case "target_discovered":
		return "目标服务已发现"
	case "attack_surface_mapped":
		return "攻击面已建立"
	case "confirmed_vector":
		return "候选攻击向量已验证"
	case "authenticated_access":
		return "已获得认证上下文"
	case "foothold":
		return "已获得受控立足点"
	case "objective_evidence":
		return "已获得目标证据"
	default:
		return strings.ReplaceAll(key, "_", " ")
	}
}

func phaseOutputCondition(phase string) string {
	switch phase {
	case "recon":
		return "target_discovered"
	case "enumeration":
		return "attack_surface_mapped"
	case "validation":
		return "confirmed_vector"
	case "credential":
		return "authenticated_access"
	case "exploit":
		return "foothold"
	case "post_exploit":
		return "objective_evidence"
	case "verify":
		return "objective_evidence"
	default:
		return ""
	}
}

func satisfyDerivedConditionTx(
	ctx context.Context,
	tx *sql.Tx,
	conversationID string,
	intent Intent,
	observation Observation,
) error {
	conditionKey := phaseOutputCondition(intent.Phase)
	if conditionKey == "" {
		return nil
	}
	scope := intentScope(intent)
	canonicalKey := "condition:" + scope + ":" + conditionKey
	condition, err := loadNodeByCanonicalTx(ctx, tx, conversationID, canonicalKey)
	if err != nil {
		return err
	}
	if condition == nil {
		condition = &Node{
			ID:             stableID("condition", conversationID, scope, conditionKey),
			ConversationID: conversationID,
			CanonicalKey:   canonicalKey,
			Label:          prerequisiteLabel(conditionKey),
			Alpha:          1,
			Beta:           1,
		}
	}
	condition.Kind = NodeFact
	condition.State = StateSolved
	condition.Confidence = math.Max(condition.Confidence, observation.Confidence)
	condition.Prior = condition.Confidence
	condition.Alpha++
	condition.Metadata = nonNilMap(condition.Metadata)
	condition.Metadata["condition"] = conditionKey
	condition.Metadata["scope"] = scope
	condition.Metadata["source_event"] = observation.SourceEventID
	if err := upsertNodeTx(ctx, tx, *condition); err != nil {
		return err
	}
	callKey := observation.ToolCallID
	if callKey == "" {
		callKey = observation.ExecutionID
	}
	if callKey == "" {
		callKey = observation.SourceEventID
	}
	return upsertEdgeTx(ctx, tx, Edge{
		ConversationID: conversationID,
		SourceID:       stableID("action", conversationID, callKey),
		TargetID:       condition.ID,
		Relation:       "establishes",
		Confidence:     observation.Confidence,
	})
}

// posteriorBounds uses a Wilson-style interval over the Beta posterior mean.
// It is intentionally conservative: uncertain branches retain a wide upper
// bound and therefore are not pruned prematurely.
func posteriorBounds(alpha, beta float64) (float64, float64) {
	mean := posteriorMean(alpha, beta)
	n := math.Max(1, alpha+beta-2)
	z := 1.6448536269514722 // 90% two-sided normal interval
	denominator := 1 + z*z/n
	center := (mean + z*z/(2*n)) / denominator
	margin := z * math.Sqrt((mean*(1-mean)+z*z/(4*n))/n) / denominator
	return clamp01(center - margin), clamp01(center + margin)
}

func selectIntent(intents []Intent, scores []CandidateScore) (Intent, bool) {
	if len(scores) == 0 {
		return Intent{}, false
	}
	byID := make(map[string]Intent, len(intents))
	for _, intent := range intents {
		byID[intent.ID] = intent
	}
	for _, score := range scores {
		if math.IsInf(score.Score, -1) {
			continue
		}
		intent, ok := byID[score.IntentID]
		if ok {
			return intent, true
		}
	}
	return Intent{}, false
}

func selectionReward(outcome string) (float64, bool) {
	switch outcome {
	case OutcomeProgress:
		return 1, true
	case OutcomeNegative:
		return -0.65, true
	case OutcomeNoProgress:
		return -0.30, true
	default:
		return 0, false
	}
}

func outcomeLabel(outcome string) string {
	switch outcome {
	case OutcomeProgress:
		return "获得有效证据"
	case OutcomeNoProgress:
		return "未获得新证据"
	case OutcomeNegative:
		return "获得否定证据"
	case OutcomeInvalidArgs:
		return "工具参数无效"
	case OutcomeToolUnavailable:
		return "工具暂不可用"
	case OutcomeInfrastructure:
		return "基础设施异常"
	case OutcomePolicyBlocked:
		return "策略阻断"
	default:
		return "待判定结果"
	}
}

func normalizedDurationCost(durationMS int64) float64 {
	if durationMS <= 0 {
		return 0
	}
	return math.Min(1, math.Log1p(float64(durationMS)/1000)/8)
}

func fallbackString(value, fallback string) string {
	if text := strings.TrimSpace(value); text != "" {
		return text
	}
	return fallback
}

func isPlannerControlTool(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	switch name {
	case "tool_search", "exit", "task", "skill", "write_todos",
		"taskcreate", "taskget", "taskupdate", "tasklist",
		"get_tool_execution", "wait_tool_execution", "cancel_tool_execution",
		"upsert_project_fact", "get_project_fact", "list_project_facts", "search_project_facts",
		"record_vulnerability", "list_vulnerabilities", "get_vulnerability",
		"get_asset", "query_assets", "list_knowledge_risk_types":
		return true
	}
	return strings.HasPrefix(name, "transfer_to_agent")
}

func countObservationSignatureTx(
	ctx context.Context,
	tx *sql.Tx,
	conversationID, toolName, arguments string,
) (int64, error) {
	var count int64
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM beliefpath_observations
WHERE conversation_id=? AND tool_name=? AND arguments=? AND event_type='tool_call'`,
		conversationID, toolName, arguments).Scan(&count)
	return count, err
}

func decisionForToolCallTx(
	ctx context.Context,
	tx *sql.Tx,
	conversationID, toolCallID string,
) (*Decision, error) {
	if strings.TrimSpace(toolCallID) == "" {
		return nil, nil
	}
	row := tx.QueryRowContext(ctx, `SELECT id, conversation_id, run_id, agent_name,
graph_revision, mode, variant, selected_intent_id, candidates_json,
tool_slate_json, created_at
FROM beliefpath_decisions
WHERE id=(
	SELECT decision_id FROM beliefpath_action_bindings
	WHERE conversation_id=? AND tool_call_id=?
)
ORDER BY created_at DESC, rowid DESC LIMIT 1`, conversationID, toolCallID)
	var decision Decision
	var selectedIntentID, candidates, tools string
	var createdAt int64
	err := row.Scan(
		&decision.ID, &decision.ConversationID, &decision.RunID,
		&decision.AgentName, &decision.GraphRevision, &decision.Mode,
		&decision.Variant, &selectedIntentID, &candidates, &tools, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(candidates), &decision.Candidates)
	_ = json.Unmarshal([]byte(tools), &decision.ToolSlate)
	decision.CreatedAt = time.UnixMilli(createdAt)
	nodes, err := loadNodesTx(ctx, tx, conversationID, NodeIntent)
	if err == nil {
		for _, node := range nodes {
			if node.ID == selectedIntentID {
				decision.Intent = intentFromNode(node)
				break
			}
		}
	}
	return &decision, nil
}

func revisionTx(ctx context.Context, tx *sql.Tx, conversationID string) (int64, error) {
	var revision int64
	err := tx.QueryRowContext(ctx,
		`SELECT revision FROM beliefpath_runs WHERE conversation_id=?`,
		conversationID,
	).Scan(&revision)
	return revision, err
}

func loadNodesTx(ctx context.Context, tx *sql.Tx, conversationID, kind string) ([]Node, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, conversation_id, kind,
canonical_key, label, state, confidence, prior, value, alpha, beta, visits,
successes, failures, repeat_count, cooldown_until_revision, metadata_json,
created_at, updated_at
FROM beliefpath_nodes WHERE conversation_id=? AND kind=?
ORDER BY created_at ASC, id ASC`, conversationID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []Node
	for rows.Next() {
		var node Node
		var metadata string
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&node.ID, &node.ConversationID, &node.Kind, &node.CanonicalKey,
			&node.Label, &node.State, &node.Confidence, &node.Prior, &node.Value,
			&node.Alpha, &node.Beta, &node.Visits, &node.Successes, &node.Failures,
			&node.RepeatCount, &node.CooldownUntilRevision, &metadata,
			&createdAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(metadata), &node.Metadata)
		node.Metadata = nonNilMap(node.Metadata)
		node.CreatedAt = time.UnixMilli(createdAt)
		node.UpdatedAt = time.UnixMilli(updatedAt)
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func loadNodeByCanonicalTx(
	ctx context.Context,
	tx *sql.Tx,
	conversationID, canonicalKey string,
) (*Node, error) {
	row := tx.QueryRowContext(ctx, `SELECT id, conversation_id, kind,
canonical_key, label, state, confidence, prior, value, alpha, beta, visits,
successes, failures, repeat_count, cooldown_until_revision, metadata_json,
created_at, updated_at
FROM beliefpath_nodes WHERE conversation_id=? AND canonical_key=?`,
		conversationID, canonicalKey)
	var node Node
	var metadata string
	var createdAt, updatedAt int64
	err := row.Scan(
		&node.ID, &node.ConversationID, &node.Kind, &node.CanonicalKey,
		&node.Label, &node.State, &node.Confidence, &node.Prior, &node.Value,
		&node.Alpha, &node.Beta, &node.Visits, &node.Successes, &node.Failures,
		&node.RepeatCount, &node.CooldownUntilRevision, &metadata,
		&createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(metadata), &node.Metadata)
	node.Metadata = nonNilMap(node.Metadata)
	node.CreatedAt = time.UnixMilli(createdAt)
	node.UpdatedAt = time.UnixMilli(updatedAt)
	return &node, nil
}

func loadNodeByIDTx(ctx context.Context, tx *sql.Tx, nodeID string) (*Node, error) {
	row := tx.QueryRowContext(ctx, `SELECT id, conversation_id, kind,
canonical_key, label, state, confidence, prior, value, alpha, beta, visits,
successes, failures, repeat_count, cooldown_until_revision, metadata_json,
created_at, updated_at
FROM beliefpath_nodes WHERE id=?`, nodeID)
	var node Node
	var metadata string
	var createdAt, updatedAt int64
	err := row.Scan(
		&node.ID, &node.ConversationID, &node.Kind, &node.CanonicalKey,
		&node.Label, &node.State, &node.Confidence, &node.Prior, &node.Value,
		&node.Alpha, &node.Beta, &node.Visits, &node.Successes, &node.Failures,
		&node.RepeatCount, &node.CooldownUntilRevision, &metadata,
		&createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(metadata), &node.Metadata)
	node.Metadata = nonNilMap(node.Metadata)
	node.CreatedAt = time.UnixMilli(createdAt)
	node.UpdatedAt = time.UnixMilli(updatedAt)
	return &node, nil
}

func incomingIntentTx(
	ctx context.Context,
	tx *sql.Tx,
	conversationID, actionID string,
) (*Node, error) {
	var intentID string
	err := tx.QueryRowContext(ctx, `SELECT source_id FROM beliefpath_edges
WHERE conversation_id=? AND target_id=? AND relation='executes'
ORDER BY updated_at DESC LIMIT 1`, conversationID, actionID).Scan(&intentID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return loadNodeByIDTx(ctx, tx, intentID)
}

func loadToolStatTx(
	ctx context.Context,
	tx *sql.Tx,
	toolName string,
	dimensions int,
) (toolBanditStat, error) {
	stat := newToolBanditStat(toolName, dimensions)
	var aJSON, bJSON string
	err := tx.QueryRowContext(ctx, `SELECT pulls, reward_sum, a_diag_json,
b_json, successes, failures, avg_duration_ms
FROM beliefpath_tool_stats WHERE tool_name=?`, toolName).Scan(
		&stat.Pulls, &stat.RewardSum, &aJSON, &bJSON,
		&stat.Successes, &stat.Failures, &stat.AvgDurationMS,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return stat, nil
	}
	if err != nil {
		return stat, err
	}
	_ = json.Unmarshal([]byte(aJSON), &stat.ADiag)
	_ = json.Unmarshal([]byte(bJSON), &stat.B)
	stat.ensureDimensions(dimensions)
	return stat, nil
}

func actionForExecutionTx(
	ctx context.Context,
	tx *sql.Tx,
	conversationID, executionID string,
) (toolName, nodeID string, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, metadata_json
FROM beliefpath_nodes WHERE conversation_id=? AND kind='action'`,
		conversationID)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	for rows.Next() {
		var id, metadataJSON string
		if err := rows.Scan(&id, &metadataJSON); err != nil {
			return "", "", err
		}
		var metadata map[string]interface{}
		if json.Unmarshal([]byte(metadataJSON), &metadata) != nil {
			continue
		}
		if stringValue(metadata["execution_id"]) == executionID {
			return stringValue(metadata["tool_name"]), id, nil
		}
	}
	return "", "", rows.Err()
}

func (s *Service) logWarn(message string, err error, conversationID string) {
	if s == nil || s.logger == nil {
		return
	}
	s.logger.Warn(message,
		zap.Error(err),
		zap.String("conversation_id", conversationID),
	)
}

func sortStringsUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
