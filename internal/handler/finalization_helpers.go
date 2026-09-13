package handler

import (
	"balancelee-ai/beliefpath"
	"context"
	"fmt"
	"strings"
	"time"

	"balancelee-ai/internal/agentfinalizer"
	"balancelee-ai/internal/multiagent"

	"go.uber.org/zap"
)

func (h *AgentHandler) finalizeAgentRunForDelivery(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	result *multiagent.RunResult,
	mcpExecutionIDs []string,
	reasoningContent string,
) agentfinalizer.Decision {
	return h.finalizeAgentRunForDeliveryWithPolicy(conversationID, assistantMessageID, agentMode, result, mcpExecutionIDs, reasoningContent, false)
}

func (h *AgentHandler) finalizeAgentRunForDeliveryWithPolicy(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	result *multiagent.RunResult,
	mcpExecutionIDs []string,
	reasoningContent string,
	requireExecutionEvidence bool,
) agentfinalizer.Decision {
	decision := agentfinalizer.FromRunResult(h.db, result, agentfinalizer.Input{
		ConversationID:           conversationID,
		AssistantMessageID:       assistantMessageID,
		AgentMode:                agentMode,
		MCPExecutionIDs:          mcpExecutionIDs,
		RequireExecutionEvidence: requireExecutionEvidence,
	})
	h.persistFinalizationDecision(conversationID, assistantMessageID, agentMode, mcpExecutionIDs, reasoningContent, decision)
	return decision
}

func (h *AgentHandler) decideAgentRunForDeliveryWithPolicy(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	result *multiagent.RunResult,
	mcpExecutionIDs []string,
	requireExecutionEvidence bool,
) agentfinalizer.Decision {
	return agentfinalizer.FromRunResult(h.db, result, agentfinalizer.Input{
		ConversationID:           conversationID,
		AssistantMessageID:       assistantMessageID,
		AgentMode:                agentMode,
		MCPExecutionIDs:          mcpExecutionIDs,
		RequireExecutionEvidence: requireExecutionEvidence,
	})
}

func (h *AgentHandler) decideAgentRunForDelivery(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	result *multiagent.RunResult,
	mcpExecutionIDs []string,
) agentfinalizer.Decision {
	return agentfinalizer.FromRunResult(h.db, result, agentfinalizer.Input{
		ConversationID:           conversationID,
		AssistantMessageID:       assistantMessageID,
		AgentMode:                agentMode,
		MCPExecutionIDs:          mcpExecutionIDs,
		RequireExecutionEvidence: false,
	})
}

func (h *AgentHandler) persistFinalizationDecision(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	mcpExecutionIDs []string,
	reasoningContent string,
	decision agentfinalizer.Decision,
) *beliefpath.RunSummary {
	if assistantMessageID == "" || h.db == nil {
		return nil
	}
	_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "finalization_check", finalizationCheckMessage(decision), decision)
	summary := h.observeBeliefPathFinalization(conversationID, assistantMessageID, decision)
	h.persistBeliefPathSummary(assistantMessageID, conversationID, summary)
	if decision.Finalizable {
		if err := h.db.UpdateAssistantMessageFinalize(assistantMessageID, decision.FinalText, mcpExecutionIDs, reasoningContent); err != nil && h.logger != nil {
			h.logger.Warn("更新最终助手消息失败", zap.Error(err), zap.String("conversationId", conversationID), zap.String("agentMode", agentMode))
		}
		return summary
	}
	_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", finalizationBlockedMessage(decision), time.Now(), assistantMessageID)
	return summary
}

func (h *AgentHandler) finalizeCandidateForDelivery(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	response string,
	mcpExecutionIDs []string,
	awaitingHITL bool,
	reasoningContent string,
) agentfinalizer.Decision {
	return h.finalizeCandidateForDeliveryWithPolicy(conversationID, assistantMessageID, agentMode, response, mcpExecutionIDs, awaitingHITL, reasoningContent, false)
}

func (h *AgentHandler) finalizeCandidateForDeliveryWithPolicy(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	response string,
	mcpExecutionIDs []string,
	awaitingHITL bool,
	reasoningContent string,
	requireExecutionEvidence bool,
) agentfinalizer.Decision {
	decision := agentfinalizer.Decide(h.db, agentfinalizer.Input{
		Response:                 response,
		ConversationID:           conversationID,
		AssistantMessageID:       assistantMessageID,
		AgentMode:                agentMode,
		MCPExecutionIDs:          mcpExecutionIDs,
		AwaitingHITL:             awaitingHITL,
		RequireExecutionEvidence: requireExecutionEvidence,
	})
	if assistantMessageID == "" || h.db == nil {
		return decision
	}
	_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "finalization_check", finalizationCheckMessage(decision), decision)
	summary := h.observeBeliefPathFinalization(conversationID, assistantMessageID, decision)
	h.persistBeliefPathSummary(assistantMessageID, conversationID, summary)
	if decision.Finalizable {
		if err := h.db.UpdateAssistantMessageFinalize(assistantMessageID, decision.FinalText, mcpExecutionIDs, reasoningContent); err != nil && h.logger != nil {
			h.logger.Warn("更新最终助手消息失败", zap.Error(err), zap.String("conversationId", conversationID), zap.String("agentMode", agentMode))
		}
		return decision
	}
	_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", finalizationBlockedMessage(decision), time.Now(), assistantMessageID)
	return decision
}

func (h *AgentHandler) observeBeliefPathFinalization(
	conversationID string,
	assistantMessageID string,
	decision agentfinalizer.Decision,
) *beliefpath.RunSummary {
	if h == nil || h.beliefPath == nil {
		return nil
	}
	if err := h.beliefPath.Finalize(context.Background(), beliefpath.TerminalEvidence{
		ConversationID: conversationID,
		MessageID:      assistantMessageID,
		Status:         decision.Status,
		Verified:       decision.Finalizable && decision.EvidenceVerified,
		EvidenceRefs:   append([]string(nil), decision.EvidenceRefs...),
		FinalText:      decision.FinalText,
	}); err != nil && h.logger != nil {
		h.logger.Warn("BeliefPath 处理终态证据失败",
			zap.Error(err),
			zap.String("conversationId", conversationID))
		return nil
	}
	summary, err := h.beliefPath.BuildSummary(context.Background(), conversationID, assistantMessageID)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("BeliefPath 汇总运行数据失败",
				zap.Error(err),
				zap.String("conversationId", conversationID),
				zap.String("messageId", assistantMessageID))
		}
		return nil
	}
	return summary
}

func (h *AgentHandler) persistBeliefPathSummary(
	assistantMessageID, conversationID string,
	summary *beliefpath.RunSummary,
) {
	if h == nil || h.db == nil || summary == nil || !summary.Available {
		return
	}
	var detailID string
	err := h.db.QueryRow(`SELECT id FROM process_details
WHERE message_id=? AND event_type='beliefpath_summary'
ORDER BY created_at DESC, rowid DESC LIMIT 1`, assistantMessageID).Scan(&detailID)
	if err == nil && strings.TrimSpace(detailID) != "" {
		if updateErr := h.db.UpdateProcessDetailContent(detailID, summary.Message(), summary); updateErr == nil {
			return
		}
	}
	if addErr := h.db.AddProcessDetail(
		assistantMessageID,
		conversationID,
		"beliefpath_summary",
		summary.Message(),
		summary,
	); addErr != nil && h.logger != nil {
		h.logger.Warn("保存 BeliefPath 执行摘要失败",
			zap.Error(addErr),
			zap.String("conversationId", conversationID),
			zap.String("messageId", assistantMessageID))
	}
}

func finalizationCheckMessage(d agentfinalizer.Decision) string {
	if d.Finalizable {
		return "最终回复检查通过。"
	}
	return finalizationBlockedMessage(d)
}

func finalizationBlockedMessage(d agentfinalizer.Decision) string {
	parts := []string{"任务尚未达到最终回复条件，暂不生成成功结论。"}
	if d.CompletionReason != "" {
		parts = append(parts, "原因: "+d.CompletionReason)
	}
	if len(d.PendingExecutionIDs) > 0 {
		parts = append(parts, fmt.Sprintf("仍有 %d 个工具执行未结束: %s", len(d.PendingExecutionIDs), strings.Join(d.PendingExecutionIDs, ", ")))
	}
	if len(d.MissingChecks) > 0 {
		parts = append(parts, "缺失检查: "+strings.Join(d.MissingChecks, "; "))
	}
	return strings.Join(parts, "\n")
}

func finalizationResponsePayload(d agentfinalizer.Decision, extra map[string]interface{}) map[string]interface{} {
	return agentfinalizer.ResponsePayload(d, extra)
}

func requestRequiresExecutionEvidence(req *ChatRequest) bool {
	return req != nil && req.Finalization.RequireExecutionEvidence != nil && *req.Finalization.RequireExecutionEvidence
}
