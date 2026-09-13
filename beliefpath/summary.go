package beliefpath

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type NamedCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type BranchSummary struct {
	IntentID    string `json:"intent_id"`
	Label       string `json:"label"`
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
	PruneCount  int64  `json:"prune_count,omitempty"`
	ReopenCount int64  `json:"reopen_count,omitempty"`
}

type RunSummary struct {
	Available        bool            `json:"available"`
	ConversationID   string          `json:"conversation_id"`
	MessageID        string          `json:"message_id,omitempty"`
	RunID            string          `json:"run_id,omitempty"`
	Mode             string          `json:"mode"`
	Variant          string          `json:"variant"`
	Status           string          `json:"status"`
	GraphRevision    int64           `json:"graph_revision"`
	DecisionCount    int64           `json:"decision_count"`
	SelectedIntents  []string        `json:"selected_intents"`
	CurrentIntent    string          `json:"current_intent,omitempty"`
	CurrentToolSlate []string        `json:"current_tool_slate"`
	ToolCalls        int64           `json:"tool_calls"`
	UniqueToolCalls  int64           `json:"unique_tool_calls"`
	ToolCounts       []NamedCount    `json:"tool_counts"`
	GateAllowed      int64           `json:"gate_allowed"`
	GateBlocked      int64           `json:"gate_blocked"`
	PromptTokens     int64           `json:"prompt_tokens"`
	CompletionTokens int64           `json:"completion_tokens"`
	TotalTokens      int64           `json:"total_tokens"`
	ElapsedMS        int64           `json:"elapsed_ms"`
	NodeCount        int64           `json:"node_count"`
	EdgeCount        int64           `json:"edge_count"`
	HyperedgeCount   int64           `json:"hyperedge_count"`
	CreditCount      int64           `json:"credit_count"`
	PrunedBranches   []BranchSummary `json:"pruned_branches"`
	ReopenedBranches []BranchSummary `json:"reopened_branches"`
	GeneratedAt      time.Time       `json:"generated_at"`
}

func (s *Service) BuildSummary(
	ctx context.Context,
	conversationID, messageID string,
) (*RunSummary, error) {
	if !s.Active() {
		return nil, nil
	}
	conversationID = strings.TrimSpace(conversationID)
	messageID = strings.TrimSpace(messageID)
	if conversationID == "" {
		return nil, errors.New("conversation id is required")
	}
	summary := &RunSummary{
		Available:        true,
		ConversationID:   conversationID,
		MessageID:        messageID,
		SelectedIntents:  []string{},
		CurrentToolSlate: []string{},
		ToolCounts:       []NamedCount{},
		PrunedBranches:   []BranchSummary{},
		ReopenedBranches: []BranchSummary{},
		GeneratedAt:      time.Now(),
	}
	var createdAt, updatedAt int64
	err := s.store.db.QueryRowContext(ctx, `SELECT run_id, mode, variant,
revision, status, created_at, updated_at
FROM beliefpath_runs WHERE conversation_id=?`, conversationID).Scan(
		&summary.RunID, &summary.Mode, &summary.Variant,
		&summary.GraphRevision, &summary.Status, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	decisionIDs := make([]string, 0)
	intentIDs := make([]string, 0)
	toolCounts := make(map[string]int64)
	callSignatures := make(map[string]struct{})
	query := `SELECT event_type, COALESCE(data,''), created_at
FROM process_details WHERE conversation_id=?`
	args := []interface{}{conversationID}
	if messageID != "" {
		query += ` AND message_id=?`
		args = append(args, messageID)
	}
	query += ` ORDER BY created_at ASC, rowid ASC`
	rows, err := s.store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var firstEvent, lastEvent time.Time
	for rows.Next() {
		var eventType, dataJSON string
		var created time.Time
		if err := rows.Scan(&eventType, &dataJSON, &created); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if firstEvent.IsZero() || created.Before(firstEvent) {
			firstEvent = created
		}
		if lastEvent.IsZero() || created.After(lastEvent) {
			lastEvent = created
		}
		var data map[string]interface{}
		_ = json.Unmarshal([]byte(dataJSON), &data)
		switch eventType {
		case "beliefpath_decision":
			summary.DecisionCount++
			decisionIDs = append(decisionIDs, firstString(data, "decisionId", "decision_id"))
			intentIDs = append(intentIDs, firstString(data, "intentId", "intent_id"))
			summary.SelectedIntents = appendUniqueString(
				summary.SelectedIntents,
				firstString(data, "intent"),
			)
		case "beliefpath_gate_allowed":
			summary.GateAllowed++
		case "beliefpath_gate_blocked":
			summary.GateBlocked++
		case "tool_call":
			summary.ToolCalls++
			toolName := firstString(data, "toolName", "tool_name")
			arguments := canonicalJSON(firstValue(data, "argumentsObj", "arguments", "args"))
			toolCounts[toolName]++
			callSignatures[strings.ToLower(toolName)+"\x00"+arguments] = struct{}{}
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	summary.UniqueToolCalls = int64(len(callSignatures))
	if !firstEvent.IsZero() && !lastEvent.IsZero() && lastEvent.After(firstEvent) {
		summary.ElapsedMS = lastEvent.Sub(firstEvent).Milliseconds()
	}
	for name, count := range toolCounts {
		if strings.TrimSpace(name) != "" {
			summary.ToolCounts = append(summary.ToolCounts, NamedCount{Name: name, Count: count})
		}
	}
	sort.Slice(summary.ToolCounts, func(i, j int) bool {
		if summary.ToolCounts[i].Count == summary.ToolCounts[j].Count {
			return summary.ToolCounts[i].Name < summary.ToolCounts[j].Name
		}
		return summary.ToolCounts[i].Count > summary.ToolCounts[j].Count
	})

	if messageID != "" {
		_ = s.store.db.QueryRowContext(ctx, `SELECT
COALESCE(SUM(prompt_tokens),0),
COALESCE(SUM(completion_tokens),0),
COALESCE(SUM(total_tokens),0)
FROM model_token_usage WHERE message_id=?`, messageID).Scan(
			&summary.PromptTokens,
			&summary.CompletionTokens,
			&summary.TotalTokens,
		)
	}
	for table, destination := range map[string]*int64{
		"beliefpath_nodes":      &summary.NodeCount,
		"beliefpath_edges":      &summary.EdgeCount,
		"beliefpath_hyperedges": &summary.HyperedgeCount,
	} {
		_ = s.store.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM "+table+" WHERE conversation_id=?",
			conversationID,
		).Scan(destination)
	}
	if summary.RunID != "" {
		_ = s.store.db.QueryRowContext(ctx, `SELECT COUNT(*)
FROM beliefpath_credit_events WHERE conversation_id=? AND run_id=?`,
			conversationID, summary.RunID,
		).Scan(&summary.CreditCount)
	} else {
		_ = s.store.db.QueryRowContext(ctx, `SELECT COUNT(*)
FROM beliefpath_credit_events WHERE conversation_id=?`,
			conversationID,
		).Scan(&summary.CreditCount)
	}

	latestDecisionID := lastNonEmpty(decisionIDs)
	latestIntentID := lastNonEmpty(intentIDs)
	if latestDecisionID != "" {
		var slateJSON string
		if err := s.store.db.QueryRowContext(ctx,
			`SELECT tool_slate_json FROM beliefpath_decisions WHERE id=?`,
			latestDecisionID,
		).Scan(&slateJSON); err == nil {
			var slate []ToolScore
			if json.Unmarshal([]byte(slateJSON), &slate) == nil {
				summary.CurrentToolSlate = toolScoreNames(slate)
			}
		}
	}
	scope := ""
	if latestIntentID != "" {
		var canonicalKey, label string
		if err := s.store.db.QueryRowContext(ctx,
			`SELECT canonical_key, label FROM beliefpath_nodes WHERE id=?`,
			latestIntentID,
		).Scan(&canonicalKey, &label); err == nil {
			summary.CurrentIntent = label
			scope = intentScopeFromCanonical(canonicalKey)
		}
	}
	if err := s.collectBranchSummary(ctx, summary, scope); err != nil {
		return nil, err
	}
	return summary, nil
}

func (s *Service) collectBranchSummary(
	ctx context.Context,
	summary *RunSummary,
	scope string,
) error {
	nodes, err := s.store.loadNodes(ctx, summary.ConversationID, NodeIntent)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if scope != "" && intentScopeFromCanonical(node.CanonicalKey) != scope {
			continue
		}
		branch := BranchSummary{
			IntentID:    node.ID,
			Label:       node.Label,
			State:       node.State,
			Reason:      stringValue(node.Metadata["state_reason"]),
			PruneCount:  int64Value(node.Metadata["prune_count"]),
			ReopenCount: int64Value(node.Metadata["reopen_count"]),
		}
		if node.State == StateSuspended ||
			node.State == StatePrunedHard ||
			node.State == StateBlockedPolicy ||
			node.State == StateCooling ||
			branch.PruneCount > 0 {
			summary.PrunedBranches = append(summary.PrunedBranches, branch)
		}
		if branch.ReopenCount > 0 {
			summary.ReopenedBranches = append(summary.ReopenedBranches, branch)
		}
	}
	return nil
}

func (s RunSummary) Message() string {
	elapsed := "-"
	if s.ElapsedMS > 0 {
		elapsed = (time.Duration(s.ElapsedMS) * time.Millisecond).Round(time.Millisecond).String()
	}
	return fmt.Sprintf(
		"%s / %s · 决策 %d · 工具 %d · Token %d · 耗时 %s · 剪枝 %d · 重开 %d · 信用 %d",
		s.Mode,
		s.Variant,
		s.DecisionCount,
		s.ToolCalls,
		s.TotalTokens,
		elapsed,
		len(s.PrunedBranches),
		len(s.ReopenedBranches),
		s.CreditCount,
	)
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func lastNonEmpty(values []string) string {
	for index := len(values) - 1; index >= 0; index-- {
		if value := strings.TrimSpace(values[index]); value != "" {
			return value
		}
	}
	return ""
}

func intentScopeFromCanonical(canonicalKey string) string {
	canonicalKey = strings.TrimPrefix(strings.TrimSpace(canonicalKey), "intent:")
	if index := strings.Index(canonicalKey, ":"); index > 0 {
		return canonicalKey[:index]
	}
	return ""
}
