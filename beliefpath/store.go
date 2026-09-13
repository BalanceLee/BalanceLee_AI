package beliefpath

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type store struct {
	db *sql.DB
}

func newStore(db *sql.DB) *store {
	return &store{db: db}
}

func (s *store) ensureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("beliefpath database is unavailable")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS beliefpath_runs (
			conversation_id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			mode TEXT NOT NULL,
			variant TEXT NOT NULL,
			revision INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			goal TEXT NOT NULL DEFAULT '',
			config_json TEXT NOT NULL DEFAULT '{}',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS beliefpath_nodes (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			canonical_key TEXT NOT NULL,
			label TEXT NOT NULL,
			state TEXT NOT NULL DEFAULT 'active',
			confidence REAL NOT NULL DEFAULT 0.5,
			prior REAL NOT NULL DEFAULT 0.5,
			value REAL NOT NULL DEFAULT 0,
			alpha REAL NOT NULL DEFAULT 1,
			beta REAL NOT NULL DEFAULT 1,
			visits INTEGER NOT NULL DEFAULT 0,
			successes INTEGER NOT NULL DEFAULT 0,
			failures INTEGER NOT NULL DEFAULT 0,
			repeat_count INTEGER NOT NULL DEFAULT 0,
			cooldown_until_revision INTEGER NOT NULL DEFAULT 0,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			UNIQUE (conversation_id, canonical_key),
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS beliefpath_edges (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			target_id TEXT NOT NULL,
			relation TEXT NOT NULL,
			confidence REAL NOT NULL DEFAULT 0.5,
			cost REAL NOT NULL DEFAULT 0,
			risk REAL NOT NULL DEFAULT 0,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			UNIQUE (conversation_id, source_id, target_id, relation),
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS beliefpath_hyperedges (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			target_id TEXT NOT NULL,
			member_ids_json TEXT NOT NULL DEFAULT '[]',
			confidence REAL NOT NULL DEFAULT 0.5,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS beliefpath_observations (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			message_id TEXT NOT NULL DEFAULT '',
			source_event_id TEXT NOT NULL,
			run_id TEXT NOT NULL DEFAULT '',
			agent_name TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			execution_id TEXT NOT NULL DEFAULT '',
			tool_name TEXT NOT NULL DEFAULT '',
			event_type TEXT NOT NULL,
			outcome TEXT NOT NULL,
			content TEXT NOT NULL DEFAULT '',
			arguments TEXT NOT NULL DEFAULT '',
			confidence REAL NOT NULL DEFAULT 0.5,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			data_json TEXT NOT NULL DEFAULT '{}',
			created_at INTEGER NOT NULL,
			UNIQUE (conversation_id, source_event_id),
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS beliefpath_decisions (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			run_id TEXT NOT NULL DEFAULT '',
			agent_name TEXT NOT NULL DEFAULT '',
			graph_revision INTEGER NOT NULL,
			mode TEXT NOT NULL,
			variant TEXT NOT NULL,
			selected_intent_id TEXT NOT NULL DEFAULT '',
			selected_tool TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			candidates_json TEXT NOT NULL DEFAULT '[]',
			tool_slate_json TEXT NOT NULL DEFAULT '[]',
			outcome TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS beliefpath_action_bindings (
			conversation_id TEXT NOT NULL,
			tool_call_id TEXT NOT NULL,
			decision_id TEXT NOT NULL,
			intent_id TEXT NOT NULL DEFAULT '',
			tool_name TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			PRIMARY KEY (conversation_id, tool_call_id),
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
			FOREIGN KEY (decision_id) REFERENCES beliefpath_decisions(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS beliefpath_tool_stats (
			tool_name TEXT PRIMARY KEY,
			pulls INTEGER NOT NULL DEFAULT 0,
			reward_sum REAL NOT NULL DEFAULT 0,
			a_diag_json TEXT NOT NULL DEFAULT '[]',
			b_json TEXT NOT NULL DEFAULT '[]',
			successes INTEGER NOT NULL DEFAULT 0,
			failures INTEGER NOT NULL DEFAULT 0,
			avg_duration_ms REAL NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS beliefpath_credit_events (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			run_id TEXT NOT NULL DEFAULT '',
			node_id TEXT NOT NULL DEFAULT '',
			tool_name TEXT NOT NULL DEFAULT '',
			credit_type TEXT NOT NULL,
			reward REAL NOT NULL DEFAULT 0,
			evidence_refs_json TEXT NOT NULL DEFAULT '[]',
			created_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_beliefpath_nodes_conversation ON beliefpath_nodes(conversation_id, kind, state)`,
		`CREATE INDEX IF NOT EXISTS idx_beliefpath_edges_conversation ON beliefpath_edges(conversation_id, source_id, target_id)`,
		`CREATE INDEX IF NOT EXISTS idx_beliefpath_observations_conversation ON beliefpath_observations(conversation_id, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_beliefpath_observations_tool_call ON beliefpath_observations(conversation_id, tool_call_id)`,
		`CREATE INDEX IF NOT EXISTS idx_beliefpath_decisions_conversation ON beliefpath_decisions(conversation_id, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_beliefpath_decisions_tool_call ON beliefpath_decisions(conversation_id, tool_call_id)`,
		`CREATE INDEX IF NOT EXISTS idx_beliefpath_bindings_decision ON beliefpath_action_bindings(decision_id)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize beliefpath schema: %w", err)
		}
	}
	return nil
}

func (s *store) ensureRun(ctx context.Context, conversationID, runID, goal string, cfg Config) error {
	now := time.Now().UnixMilli()
	configJSON, _ := json.Marshal(cfg)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO beliefpath_runs (
	conversation_id, run_id, mode, variant, revision, status, goal,
	config_json, created_at, updated_at
) VALUES (?, ?, ?, ?, 0, 'active', ?, ?, ?, ?)
ON CONFLICT(conversation_id) DO UPDATE SET
	run_id=CASE WHEN excluded.run_id<>'' THEN excluded.run_id ELSE beliefpath_runs.run_id END,
	mode=excluded.mode,
	variant=excluded.variant,
	status=CASE
		WHEN excluded.goal<>'' AND excluded.goal<>beliefpath_runs.goal THEN 'active'
		ELSE beliefpath_runs.status
	END,
	goal=CASE WHEN excluded.goal<>'' THEN excluded.goal ELSE beliefpath_runs.goal END,
	config_json=excluded.config_json,
	updated_at=excluded.updated_at`,
		conversationID, runID, cfg.Mode, cfg.Variant, goal, string(configJSON), now, now)
	return err
}

func (s *store) revision(ctx context.Context, conversationID string) (int64, error) {
	var revision int64
	err := s.db.QueryRowContext(ctx,
		`SELECT revision FROM beliefpath_runs WHERE conversation_id=?`,
		conversationID,
	).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return revision, err
}

func bumpRevisionTx(ctx context.Context, tx *sql.Tx, conversationID string) (int64, error) {
	now := time.Now().UnixMilli()
	if _, err := tx.ExecContext(ctx,
		`UPDATE beliefpath_runs SET revision=revision+1, updated_at=? WHERE conversation_id=?`,
		now, conversationID,
	); err != nil {
		return 0, err
	}
	var revision int64
	if err := tx.QueryRowContext(ctx,
		`SELECT revision FROM beliefpath_runs WHERE conversation_id=?`,
		conversationID,
	).Scan(&revision); err != nil {
		return 0, err
	}
	return revision, nil
}

func upsertNodeTx(ctx context.Context, tx *sql.Tx, node Node) error {
	now := time.Now().UnixMilli()
	if node.ID == "" {
		node.ID = stableID("node", node.ConversationID, node.CanonicalKey)
	}
	if node.State == "" {
		node.State = StateActive
	}
	if node.Alpha <= 0 {
		node.Alpha = 1
	}
	if node.Beta <= 0 {
		node.Beta = 1
	}
	metadata, _ := json.Marshal(nonNilMap(node.Metadata))
	_, err := tx.ExecContext(ctx, `
INSERT INTO beliefpath_nodes (
	id, conversation_id, kind, canonical_key, label, state, confidence,
	prior, value, alpha, beta, visits, successes, failures, repeat_count,
	cooldown_until_revision, metadata_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(conversation_id, canonical_key) DO UPDATE SET
	label=excluded.label,
	state=excluded.state,
	confidence=excluded.confidence,
	prior=excluded.prior,
	value=excluded.value,
	alpha=excluded.alpha,
	beta=excluded.beta,
	visits=excluded.visits,
	successes=excluded.successes,
	failures=excluded.failures,
	repeat_count=excluded.repeat_count,
	cooldown_until_revision=excluded.cooldown_until_revision,
	metadata_json=excluded.metadata_json,
	updated_at=excluded.updated_at`,
		node.ID, node.ConversationID, node.Kind, node.CanonicalKey, node.Label,
		node.State, clamp01(node.Confidence), clamp01(node.Prior), node.Value,
		node.Alpha, node.Beta, node.Visits, node.Successes, node.Failures,
		node.RepeatCount, node.CooldownUntilRevision, string(metadata), now, now)
	return err
}

func upsertEdgeTx(ctx context.Context, tx *sql.Tx, edge Edge) error {
	now := time.Now().UnixMilli()
	if edge.ID == "" {
		edge.ID = stableID("edge", edge.ConversationID, edge.SourceID, edge.TargetID, edge.Relation)
	}
	metadata, _ := json.Marshal(nonNilMap(edge.Metadata))
	_, err := tx.ExecContext(ctx, `
INSERT INTO beliefpath_edges (
	id, conversation_id, source_id, target_id, relation, confidence,
	cost, risk, metadata_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(conversation_id, source_id, target_id, relation) DO UPDATE SET
	confidence=excluded.confidence,
	cost=excluded.cost,
	risk=excluded.risk,
	metadata_json=excluded.metadata_json,
	updated_at=excluded.updated_at`,
		edge.ID, edge.ConversationID, edge.SourceID, edge.TargetID, edge.Relation,
		clamp01(edge.Confidence), edge.Cost, edge.Risk, string(metadata), now, now)
	return err
}

func upsertHyperedgeTx(ctx context.Context, tx *sql.Tx, edge Hyperedge) error {
	now := time.Now().UnixMilli()
	if edge.ID == "" {
		edge.ID = stableID(
			"hyperedge",
			edge.ConversationID,
			edge.Kind,
			edge.TargetID,
			strings.Join(edge.MemberIDs, ","),
		)
	}
	members, _ := json.Marshal(edge.MemberIDs)
	metadata, _ := json.Marshal(nonNilMap(edge.Metadata))
	_, err := tx.ExecContext(ctx, `
INSERT INTO beliefpath_hyperedges (
	id, conversation_id, kind, target_id, member_ids_json,
	confidence, metadata_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	kind=excluded.kind,
	target_id=excluded.target_id,
	member_ids_json=excluded.member_ids_json,
	confidence=excluded.confidence,
	metadata_json=excluded.metadata_json,
	updated_at=excluded.updated_at`,
		edge.ID, edge.ConversationID, edge.Kind, edge.TargetID,
		string(members), clamp01(edge.Confidence), string(metadata), now, now)
	return err
}

func insertObservationTx(ctx context.Context, tx *sql.Tx, observation Observation) (bool, error) {
	data, _ := json.Marshal(nonNilMap(observation.Data))
	createdAt := observation.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	result, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO beliefpath_observations (
	id, conversation_id, message_id, source_event_id, run_id, agent_name,
	tool_call_id, execution_id, tool_name, event_type, outcome, content,
	arguments, confidence, duration_ms, data_json, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		observation.ID, observation.ConversationID, observation.MessageID,
		observation.SourceEventID, observation.RunID, observation.AgentName,
		observation.ToolCallID, observation.ExecutionID, observation.ToolName,
		observation.EventType, observation.Outcome, observation.Content,
		observation.Arguments, clamp01(observation.Confidence),
		observation.DurationMS, string(data), createdAt.UnixMilli())
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected > 0, err
}

func (s *store) loadNodes(ctx context.Context, conversationID, kind string) ([]Node, error) {
	query := `SELECT id, conversation_id, kind, canonical_key, label, state,
confidence, prior, value, alpha, beta, visits, successes, failures,
repeat_count, cooldown_until_revision, metadata_json, created_at, updated_at
FROM beliefpath_nodes WHERE conversation_id=?`
	args := []interface{}{conversationID}
	if strings.TrimSpace(kind) != "" {
		query += ` AND kind=?`
		args = append(args, kind)
	}
	query += ` ORDER BY created_at ASC, id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
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

func (s *store) loadEdges(ctx context.Context, conversationID string) ([]Edge, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, conversation_id, source_id,
target_id, relation, confidence, cost, risk, metadata_json, created_at, updated_at
FROM beliefpath_edges WHERE conversation_id=? ORDER BY created_at ASC, id ASC`,
		conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edges []Edge
	for rows.Next() {
		var edge Edge
		var metadata string
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&edge.ID, &edge.ConversationID, &edge.SourceID, &edge.TargetID,
			&edge.Relation, &edge.Confidence, &edge.Cost, &edge.Risk,
			&metadata, &createdAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(metadata), &edge.Metadata)
		edge.Metadata = nonNilMap(edge.Metadata)
		edge.CreatedAt = time.UnixMilli(createdAt)
		edge.UpdatedAt = time.UnixMilli(updatedAt)
		edges = append(edges, edge)
	}
	return edges, rows.Err()
}

func (s *store) loadHyperedges(ctx context.Context, conversationID string) ([]Hyperedge, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, conversation_id, kind,
target_id, member_ids_json, confidence, metadata_json
FROM beliefpath_hyperedges WHERE conversation_id=? ORDER BY created_at ASC, id ASC`,
		conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hyperedges []Hyperedge
	for rows.Next() {
		var item Hyperedge
		var members, metadata string
		if err := rows.Scan(
			&item.ID, &item.ConversationID, &item.Kind, &item.TargetID,
			&members, &item.Confidence, &metadata,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(members), &item.MemberIDs)
		_ = json.Unmarshal([]byte(metadata), &item.Metadata)
		item.Metadata = nonNilMap(item.Metadata)
		hyperedges = append(hyperedges, item)
	}
	return hyperedges, rows.Err()
}

func insertDecisionTx(ctx context.Context, tx *sql.Tx, decision Decision) error {
	candidates, _ := json.Marshal(decision.Candidates)
	toolSlate, _ := json.Marshal(decision.ToolSlate)
	now := decision.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}
	selectedTool := ""
	if len(decision.ToolSlate) > 0 {
		selectedTool = decision.ToolSlate[0].Name
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO beliefpath_decisions (
	id, conversation_id, run_id, agent_name, graph_revision, mode, variant,
	selected_intent_id, selected_tool, candidates_json, tool_slate_json,
	created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		decision.ID, decision.ConversationID, decision.RunID, decision.AgentName,
		decision.GraphRevision, decision.Mode, decision.Variant,
		decision.Intent.ID, selectedTool, string(candidates), string(toolSlate),
		now.UnixMilli(), now.UnixMilli())
	return err
}

func (s *store) bindDecisionToolCall(
	ctx context.Context,
	decisionID, conversationID, toolCallID, toolName string,
) error {
	if decisionID == "" || strings.TrimSpace(toolCallID) == "" {
		return nil
	}
	var intentID string
	_ = s.db.QueryRowContext(ctx,
		`SELECT selected_intent_id FROM beliefpath_decisions WHERE id=? AND conversation_id=?`,
		decisionID, conversationID,
	).Scan(&intentID)
	now := time.Now().UnixMilli()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO beliefpath_action_bindings (
	conversation_id, tool_call_id, decision_id, intent_id, tool_name, created_at
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(conversation_id, tool_call_id) DO UPDATE SET
	decision_id=excluded.decision_id,
	intent_id=excluded.intent_id,
	tool_name=excluded.tool_name`,
		conversationID, toolCallID, decisionID, intentID, toolName, now)
	return err
}

func (s *store) latestDecision(ctx context.Context, conversationID, agentName string) (*Decision, error) {
	query := `SELECT id, conversation_id, run_id,
agent_name, graph_revision, mode, variant, selected_intent_id,
candidates_json, tool_slate_json, created_at
FROM beliefpath_decisions WHERE conversation_id=?`
	args := []interface{}{conversationID}
	if strings.TrimSpace(agentName) != "" {
		query += ` AND agent_name=?`
		args = append(args, strings.TrimSpace(agentName))
	}
	query += ` ORDER BY created_at DESC, rowid DESC LIMIT 1`
	row := s.db.QueryRowContext(ctx, query, args...)
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
	nodes, err := s.loadNodes(ctx, conversationID, NodeIntent)
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

func (s *store) decisionForToolCall(ctx context.Context, conversationID, toolCallID string) (*Decision, error) {
	if strings.TrimSpace(toolCallID) == "" {
		return nil, nil
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, conversation_id, run_id,
agent_name, graph_revision, mode, variant, selected_intent_id,
candidates_json, tool_slate_json, created_at
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
	nodes, err := s.loadNodes(ctx, conversationID, NodeIntent)
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

func (s *store) loadToolStat(ctx context.Context, toolName string, dimensions int) (toolBanditStat, error) {
	stat := newToolBanditStat(toolName, dimensions)
	var aJSON, bJSON string
	err := s.db.QueryRowContext(ctx, `SELECT pulls, reward_sum, a_diag_json,
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

func (s *store) loadToolStats(ctx context.Context, dimensions int) (map[string]toolBanditStat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tool_name, pulls, reward_sum,
a_diag_json, b_json, successes, failures, avg_duration_ms
FROM beliefpath_tool_stats`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]toolBanditStat)
	for rows.Next() {
		var stat toolBanditStat
		var aJSON, bJSON string
		if err := rows.Scan(
			&stat.ToolName, &stat.Pulls, &stat.RewardSum, &aJSON, &bJSON,
			&stat.Successes, &stat.Failures, &stat.AvgDurationMS,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(aJSON), &stat.ADiag)
		_ = json.Unmarshal([]byte(bJSON), &stat.B)
		stat.ensureDimensions(dimensions)
		out[strings.ToLower(strings.TrimSpace(stat.ToolName))] = stat
	}
	return out, rows.Err()
}

func upsertToolStatTx(ctx context.Context, tx *sql.Tx, stat toolBanditStat) error {
	aJSON, _ := json.Marshal(stat.ADiag)
	bJSON, _ := json.Marshal(stat.B)
	_, err := tx.ExecContext(ctx, `
INSERT INTO beliefpath_tool_stats (
	tool_name, pulls, reward_sum, a_diag_json, b_json,
	successes, failures, avg_duration_ms, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(tool_name) DO UPDATE SET
	pulls=excluded.pulls,
	reward_sum=excluded.reward_sum,
	a_diag_json=excluded.a_diag_json,
	b_json=excluded.b_json,
	successes=excluded.successes,
	failures=excluded.failures,
	avg_duration_ms=excluded.avg_duration_ms,
	updated_at=excluded.updated_at`,
		stat.ToolName, stat.Pulls, stat.RewardSum, string(aJSON), string(bJSON),
		stat.Successes, stat.Failures, stat.AvgDurationMS, time.Now().UnixMilli())
	return err
}

func (s *store) snapshot(ctx context.Context, conversationID string) (*Snapshot, error) {
	var snapshot Snapshot
	snapshot.ConversationID = conversationID
	err := s.db.QueryRowContext(ctx,
		`SELECT revision, mode, variant FROM beliefpath_runs WHERE conversation_id=?`,
		conversationID,
	).Scan(&snapshot.Revision, &snapshot.Mode, &snapshot.Variant)
	if errors.Is(err, sql.ErrNoRows) {
		return &snapshot, nil
	}
	if err != nil {
		return nil, err
	}
	if snapshot.Nodes, err = s.loadNodes(ctx, conversationID, ""); err != nil {
		return nil, err
	}
	if snapshot.Edges, err = s.loadEdges(ctx, conversationID); err != nil {
		return nil, err
	}
	if snapshot.Hyperedges, err = s.loadHyperedges(ctx, conversationID); err != nil {
		return nil, err
	}
	snapshot.Decision, _ = s.latestDecision(ctx, conversationID, "")
	return &snapshot, nil
}

func nonNilMap(value map[string]interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}
	return value
}
