package beliefpath

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	urlPattern         = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
	ipv4Pattern        = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	flagPattern        = regexp.MustCompile(`(?i)\b(?:flag|ctf)\{[^{}\r\n]{1,256}\}`)
	credentialPattern  = regexp.MustCompile(`(?i)\b(?:user(?:name)?|login|account)\s*[:=]\s*[^\s,;]{1,80}`)
	successPattern     = regexp.MustCompile(`(?i)(login successful|authentication bypass(?:ed)?|uid=0\(|uid=33\(|shell obtained|is vulnerable|vulnerability confirmed|confirmed vulnerability|漏洞已确认|flag\{|ctf\{)`)
	noResultPattern    = regexp.MustCompile(`(?i)(no results?|not found|0 findings?|nothing found|not vulnerable|connection refused|timed? out)`)
	invalidArgPattern  = regexp.MustCompile(`(?i)(invalid .*argument|arguments?.*json|unmarshal|schema validation|required field|unknown field)`)
	infraPattern       = regexp.MustCompile(`(?i)(connection refused|network is unreachable|temporary failure|service unavailable|gateway timeout|context deadline exceeded|timed? out)`)
	unavailablePattern = regexp.MustCompile(`(?i)(command not found|executable file not found|tool .*not registered|client .*not connected|circuit .*open|temporarily unavailable)`)
	policyPattern      = regexp.MustCompile(`(?i)(blocked by|policy|permission denied|approval rejected|toolguard|out of scope|超出授权|已拦截|拒绝执行)`)
)

type Event struct {
	ConversationID string
	MessageID      string
	SourceEventID  string
	RunID          string
	AgentName      string
	EventType      string
	Message        string
	Data           interface{}
	CreatedAt      time.Time
}

type Artifact struct {
	Kind       string
	Value      string
	Confidence float64
}

func NormalizeEvent(event Event) Observation {
	data := toStringMap(event.Data)
	content := firstString(data, "result", "output", "error", "resultPreview", "content")
	if strings.TrimSpace(content) == "" {
		content = event.Message
	}
	arguments := canonicalJSON(firstValue(data, "arguments", "args", "input"))
	toolCallID := firstString(data, "toolCallId", "tool_call_id")
	executionID := firstString(data, "executionId", "execution_id", "mcpExecutionId")
	toolName := firstString(data, "toolName", "tool_name")
	runID := strings.TrimSpace(event.RunID)
	if runID == "" {
		runID = firstString(data, "runId", "run_id")
	}
	agentName := strings.TrimSpace(event.AgentName)
	if agentName == "" {
		agentName = firstString(data, "einoAgent", "agent")
	}
	createdAt := event.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	sourceID := strings.TrimSpace(event.SourceEventID)
	if sourceID == "" {
		sourceID = stableID(
			"event",
			event.ConversationID,
			event.MessageID,
			event.EventType,
			toolCallID,
			executionID,
			toolName,
			arguments,
			content,
		)
	}
	observation := Observation{
		ID:             stableID("observation", event.ConversationID, sourceID),
		ConversationID: strings.TrimSpace(event.ConversationID),
		MessageID:      strings.TrimSpace(event.MessageID),
		SourceEventID:  sourceID,
		RunID:          runID,
		AgentName:      agentName,
		ToolCallID:     toolCallID,
		ExecutionID:    executionID,
		ToolName:       toolName,
		EventType:      strings.TrimSpace(event.EventType),
		Content:        truncateText(content, 12000),
		Arguments:      truncateText(arguments, 6000),
		Confidence:     0.5,
		DurationMS:     firstInt64(data, "durationMs", "duration_ms"),
		Data:           data,
		CreatedAt:      createdAt,
	}
	observation.Outcome, observation.Confidence = classifyOutcome(observation)
	return observation
}

func classifyOutcome(observation Observation) (string, float64) {
	if observation.EventType != "tool_result" {
		return OutcomeUnknown, 0.5
	}
	text := strings.TrimSpace(observation.Content)
	lower := strings.ToLower(text)
	if firstBool(observation.Data, "blocked") || policyPattern.MatchString(text) {
		return OutcomePolicyBlocked, 0.98
	}
	if invalidArgPattern.MatchString(text) {
		return OutcomeInvalidArgs, 0.95
	}
	if unavailablePattern.MatchString(text) {
		return OutcomeToolUnavailable, 0.90
	}
	if infraPattern.MatchString(text) {
		return OutcomeInfrastructure, 0.85
	}
	isError := firstBool(observation.Data, "isError", "is_error")
	status := strings.ToLower(firstString(observation.Data, "status"))
	if status == "blocked" {
		return OutcomePolicyBlocked, 0.98
	}
	if status == "failed" || status == "error" || isError {
		return OutcomeNegative, 0.75
	}
	if text == "" || noResultPattern.MatchString(lower) {
		return OutcomeNoProgress, 0.75
	}
	if successPattern.MatchString(text) || len(ExtractArtifacts(text)) > 0 {
		return OutcomeProgress, 0.85
	}
	if status == "completed" || firstBool(observation.Data, "success") {
		return OutcomeProgress, 0.65
	}
	return OutcomeUnknown, 0.5
}

func ExtractArtifacts(content string) []Artifact {
	type artifactKey struct {
		kind  string
		value string
	}
	found := make(map[artifactKey]Artifact)
	add := func(kind, value string, confidence float64) {
		value = strings.TrimSpace(strings.TrimRight(value, ".,;:)"))
		if value == "" {
			return
		}
		key := artifactKey{kind: kind, value: strings.ToLower(value)}
		if existing, ok := found[key]; ok && existing.Confidence >= confidence {
			return
		}
		found[key] = Artifact{Kind: kind, Value: value, Confidence: confidence}
	}
	for _, value := range urlPattern.FindAllString(content, -1) {
		add("url", value, 0.92)
	}
	for _, value := range ipv4Pattern.FindAllString(content, -1) {
		if validIPv4(value) {
			add("host", value, 0.90)
		}
	}
	for _, value := range flagPattern.FindAllString(content, -1) {
		add("terminal_evidence", value, 0.99)
	}
	for _, value := range credentialPattern.FindAllString(content, -1) {
		add("credential_reference", value, 0.70)
	}
	out := make([]Artifact, 0, len(found))
	for _, artifact := range found {
		out = append(out, artifact)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].Value < out[j].Value
		}
		return out[i].Kind < out[j].Kind
	})
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

func stableID(parts ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(hash[:16])
}

func canonicalJSON(value interface{}) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		var decoded interface{}
		if json.Unmarshal([]byte(typed), &decoded) == nil {
			value = decoded
		} else {
			return strings.TrimSpace(typed)
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return strings.TrimSpace(fmt.Sprint(value))
	}
	return string(raw)
}

func toStringMap(value interface{}) map[string]interface{} {
	switch typed := value.(type) {
	case nil:
		return map[string]interface{}{}
	case map[string]interface{}:
		return typed
	case string:
		var decoded map[string]interface{}
		if json.Unmarshal([]byte(typed), &decoded) == nil {
			return decoded
		}
	default:
		raw, err := json.Marshal(value)
		if err == nil {
			var decoded map[string]interface{}
			if json.Unmarshal(raw, &decoded) == nil {
				return decoded
			}
		}
	}
	return map[string]interface{}{}
}

func firstValue(data map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := data[key]; ok {
			return value
		}
	}
	return nil
}

func firstString(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := data[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if text := strings.TrimSpace(typed); text != "" {
				return text
			}
		case json.Number:
			return typed.String()
		default:
			text := strings.TrimSpace(fmt.Sprint(value))
			if text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}

func firstBool(data map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		value, ok := data[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed
		case string:
			parsed, _ := strconv.ParseBool(strings.TrimSpace(typed))
			return parsed
		case float64:
			return typed != 0
		case int:
			return typed != 0
		}
	}
	return false
}

func firstInt64(data map[string]interface{}, keys ...string) int64 {
	for _, key := range keys {
		value, ok := data[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case int:
			return int64(typed)
		case int64:
			return typed
		case float64:
			return int64(typed)
		case json.Number:
			result, _ := typed.Int64()
			return result
		case string:
			result, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
			return result
		}
	}
	return 0
}

func validIPv4(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || number > 255 {
			return false
		}
	}
	return true
}

func truncateText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

func clamp01(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}
