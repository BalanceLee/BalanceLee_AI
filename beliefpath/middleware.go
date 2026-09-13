package beliefpath

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

const (
	directiveStart = "[BELIEFPATH_DIRECTIVE]"
	directiveEnd   = "[/BELIEFPATH_DIRECTIVE]"
)

type agenticPlannerMiddleware struct {
	*adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]
	service        *Service
	conversationID string
	agentName      string
	goal           string
	allToolInfos   []*schema.ToolInfo
	toolCatalog    []ToolDescriptor
	progress       func(eventType, message string, data interface{})
	logger         *zap.Logger
}

func NewAgenticPlannerMiddleware(
	ctx context.Context,
	service *Service,
	conversationID string,
	agentName string,
	goal string,
	tools []tool.BaseTool,
	progress func(eventType, message string, data interface{}),
	logger *zap.Logger,
) (adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage], error) {
	if service == nil || !service.Active() {
		return nil, nil
	}
	infos := make([]*schema.ToolInfo, 0, len(tools))
	catalog := make([]ToolDescriptor, 0, len(tools))
	for _, candidate := range tools {
		if candidate == nil {
			continue
		}
		info, err := candidate.Info(ctx)
		if err != nil {
			if logger != nil {
				logger.Warn("beliefpath skipped tool with unreadable schema", zap.Error(err))
			}
			continue
		}
		if info == nil || strings.TrimSpace(info.Name) == "" {
			continue
		}
		infos = append(infos, info)
		catalog = append(catalog, ToolDescriptor{
			Name:        info.Name,
			Description: info.Desc,
		})
	}
	return &agenticPlannerMiddleware{
		TypedBaseChatModelAgentMiddleware: &adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]{},
		service:                           service,
		conversationID:                    strings.TrimSpace(conversationID),
		agentName:                         strings.TrimSpace(agentName),
		goal:                              strings.TrimSpace(goal),
		allToolInfos:                      infos,
		toolCatalog:                       catalog,
		progress:                          progress,
		logger:                            logger,
	}, nil
}

func (m *agenticPlannerMiddleware) BeforeModelRewriteState(
	ctx context.Context,
	state *adk.TypedChatModelAgentState[*schema.AgenticMessage],
	modelContext *adk.TypedModelContext[*schema.AgenticMessage],
) (context.Context, *adk.TypedChatModelAgentState[*schema.AgenticMessage], error) {
	_ = modelContext
	if m == nil || m.service == nil || state == nil {
		return ctx, state, nil
	}
	if !m.service.Active() {
		state.Messages = replacePlannerDirective(state.Messages, "")
		state.ToolInfos = restoreToolInfos(m.allToolInfos, state.ToolInfos)
		state.DeferredToolInfos = nil
		return ctx, state, nil
	}
	goal := m.goal
	if goal == "" {
		goal = latestAgenticUserText(state.Messages)
	}
	decision, err := m.service.Decide(ctx, DecisionRequest{
		ConversationID: m.conversationID,
		RunID:          RunIDFromContext(ctx),
		AgentName:      m.agentName,
		Goal:           goal,
		Tools:          m.toolCatalog,
	})
	if err != nil {
		if m.logger != nil {
			m.logger.Warn("beliefpath decision failed; preserving legacy agent behavior",
				zap.Error(err),
				zap.String("conversation_id", m.conversationID),
				zap.String("agent", m.agentName))
		}
		if m.service.Enforces() {
			state.ToolInfos = restoreToolInfos(m.allToolInfos, state.ToolInfos)
			state.DeferredToolInfos = nil
		}
		return ctx, state, nil
	}
	if decision == nil {
		if m.service.Enforces() {
			state.ToolInfos = restoreToolInfos(m.allToolInfos, state.ToolInfos)
			state.DeferredToolInfos = nil
		}
		return ctx, state, nil
	}
	if directive := m.service.Directive(decision); directive != "" {
		state.Messages = replacePlannerDirective(state.Messages, directive)
	}
	if m.service.Enforces() && len(decision.ToolSlate) > 0 {
		state.ToolInfos = selectToolInfos(m.allToolInfos, state.ToolInfos, decision.ToolSlate)
		state.DeferredToolInfos = nil
	}
	if m.progress != nil {
		m.progress("beliefpath_decision", "BeliefPath 已更新当前决策", map[string]interface{}{
			"conversationId": m.conversationID,
			"agent":          m.agentName,
			"decisionId":     decision.ID,
			"graphRevision":  decision.GraphRevision,
			"mode":           decision.Mode,
			"variant":        decision.Variant,
			"intentId":       decision.Intent.ID,
			"intent":         decision.Intent.Label,
			"tools":          toolScoreNames(decision.ToolSlate),
		})
	}
	return ctx, state, nil
}

func restoreToolInfos(all, current []*schema.ToolInfo) []*schema.ToolInfo {
	out := make([]*schema.ToolInfo, 0, len(all)+8)
	seen := make(map[string]struct{}, len(all)+8)
	add := func(info *schema.ToolInfo) {
		if info == nil {
			return
		}
		name := strings.ToLower(strings.TrimSpace(info.Name))
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, info)
	}
	for _, info := range all {
		add(info)
	}
	for _, info := range current {
		if info != nil && isPlannerControlTool(info.Name) {
			add(info)
		}
	}
	return out
}

func NewToolGateMiddleware(
	service *Service,
	conversationID string,
	agentName string,
	progress func(eventType, message string, data interface{}),
) compose.ToolMiddleware {
	check := func(ctx context.Context, input *compose.ToolInput) GateDecision {
		if input == nil || service == nil || !service.Active() {
			return GateDecision{Allowed: true, Mode: ModeOff}
		}
		return service.Gate(ctx, GateRequest{
			ConversationID: conversationID,
			RunID:          RunIDFromContext(ctx),
			AgentName:      agentName,
			ToolCallID:     compose.GetToolCallID(ctx),
			ToolName:       input.Name,
			Arguments:      input.Arguments,
		})
	}
	emit := func(ctx context.Context, input *compose.ToolInput, decision GateDecision) {
		if progress == nil || input == nil {
			return
		}
		eventType := "beliefpath_gate_allowed"
		message := "BeliefPath 允许执行工具"
		if !decision.Allowed {
			eventType = "beliefpath_gate_blocked"
			message = "BeliefPath 暂停当前工具并要求重新规划"
		}
		progress(eventType, message, map[string]interface{}{
			"conversationId": conversationID,
			"agent":          agentName,
			"toolName":       input.Name,
			"toolCallId":     compose.GetToolCallID(ctx),
			"decisionId":     decision.DecisionID,
			"intentId":       decision.IntentID,
			"graphRevision":  decision.GraphRevision,
			"mode":           decision.Mode,
			"allowed":        decision.Allowed,
			"reason":         decision.Reason,
		})
	}
	blockedResult := func(input *compose.ToolInput, decision GateDecision) string {
		name := ""
		if input != nil {
			name = input.Name
		}
		return fmt.Sprintf(
			"[BeliefPath Policy Blocked] Tool %q was not executed. %s. "+
				"Review the selected intent and choose a tool from the current tool definitions.",
			name,
			decision.Reason,
		)
	}
	return compose.ToolMiddleware{
		Invokable: func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
				decision := check(ctx, input)
				emit(ctx, input, decision)
				if !decision.Allowed {
					return &compose.ToolOutput{Result: blockedResult(input, decision)}, nil
				}
				return next(ctx, input)
			}
		},
		Streamable: func(next compose.StreamableToolEndpoint) compose.StreamableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.StreamToolOutput, error) {
				decision := check(ctx, input)
				emit(ctx, input, decision)
				if !decision.Allowed {
					return &compose.StreamToolOutput{
						Result: schema.StreamReaderFromArray([]string{blockedResult(input, decision)}),
					}, nil
				}
				return next(ctx, input)
			}
		},
	}
}

func selectToolInfos(all, current []*schema.ToolInfo, slate []ToolScore) []*schema.ToolInfo {
	allowed := make(map[string]struct{}, len(slate)+12)
	for _, item := range slate {
		allowed[strings.ToLower(strings.TrimSpace(item.Name))] = struct{}{}
	}
	out := make([]*schema.ToolInfo, 0, len(allowed)+8)
	seen := make(map[string]struct{}, len(allowed)+8)
	for _, info := range all {
		if info == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(info.Name))
		if _, ok := allowed[name]; !ok && !isPlannerControlTool(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, info)
	}
	for _, info := range current {
		if info == nil || !isPlannerControlTool(info.Name) {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(info.Name))
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, info)
	}
	return out
}

func replacePlannerDirective(
	messages []*schema.AgenticMessage,
	directive string,
) []*schema.AgenticMessage {
	out := make([]*schema.AgenticMessage, 0, len(messages)+1)
	replacedSystem := false
	for _, message := range messages {
		if message == nil {
			continue
		}
		if message.Role != schema.AgenticRoleTypeSystem {
			out = append(out, message)
			continue
		}
		text := stripPlannerDirective(agenticText(message))
		if !replacedSystem {
			if text != "" && directive != "" {
				text += "\n\n"
			}
			text += directive
			if text != "" {
				out = append(out, schema.SystemAgenticMessage(text))
			}
			replacedSystem = true
		} else if text != "" {
			out = append(out, schema.SystemAgenticMessage(text))
		}
	}
	if !replacedSystem && directive != "" {
		out = append([]*schema.AgenticMessage{schema.SystemAgenticMessage(directive)}, out...)
	}
	return out
}

func stripPlannerDirective(value string) string {
	for {
		start := strings.Index(value, directiveStart)
		if start < 0 {
			break
		}
		endRelative := strings.Index(value[start:], directiveEnd)
		if endRelative < 0 {
			value = value[:start]
			break
		}
		end := start + endRelative + len(directiveEnd)
		value = value[:start] + value[end:]
	}
	return strings.TrimSpace(value)
}

func latestAgenticUserText(messages []*schema.AgenticMessage) string {
	for index := len(messages) - 1; index >= 0; index-- {
		message := messages[index]
		if message == nil || message.Role != schema.AgenticRoleTypeUser {
			continue
		}
		if text := strings.TrimSpace(agenticText(message)); text != "" {
			return text
		}
	}
	return ""
}

func agenticText(message *schema.AgenticMessage) string {
	if message == nil {
		return ""
	}
	var builder strings.Builder
	for _, block := range message.ContentBlocks {
		if block == nil {
			continue
		}
		var text string
		switch {
		case block.UserInputText != nil:
			text = block.UserInputText.Text
		case block.AssistantGenText != nil:
			text = block.AssistantGenText.Text
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(text)
	}
	return builder.String()
}

func toolScoreNames(scores []ToolScore) []string {
	names := make([]string, 0, len(scores))
	for _, score := range scores {
		if name := strings.TrimSpace(score.Name); name != "" {
			names = append(names, name)
		}
	}
	return names
}
