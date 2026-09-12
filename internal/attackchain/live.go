package attackchain

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
	"unicode/utf8"

	"balancelee-ai/internal/database"
)

// LiveChain is a deterministic graph projected from persisted tool events.
// It does not invoke a model, so it can be refreshed while an agent is running.
type LiveChain struct {
	Nodes           []Node             `json:"nodes"`
	Edges           []Edge             `json:"edges"`
	Revision        string             `json:"revision"`
	Mode            string             `json:"mode"`
	Running         bool               `json:"running"`
	Outcome         string             `json:"outcome"`
	CriticalNodeIDs []string           `json:"critical_node_ids"`
	CriticalEdgeIDs []string           `json:"critical_edge_ids"`
	CriticalPaths   []LiveCriticalPath `json:"critical_paths"`
	GeneratedAt     time.Time          `json:"generated_at"`
}

type LiveCriticalPath struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Evidence string   `json:"evidence"`
	NodeIDs  []string `json:"node_ids"`
	EdgeIDs  []string `json:"edge_ids"`
}

type liveToolBatch struct {
	parents  []string
	nodeIDs  []string
	expected int
}

// BuildLiveChain creates a stable execution graph from the conversation's
// process details. Tool results update their matching action node in place.
func BuildLiveChain(db *database.DB, conversationID string) (*LiveChain, error) {
	conversationID = strings.TrimSpace(conversationID)
	if db == nil || conversationID == "" {
		return nil, fmt.Errorf("conversation id is required")
	}
	conversation, err := db.GetConversation(conversationID)
	if err != nil {
		return nil, err
	}
	detailsByMessage, err := db.GetProcessDetailsByConversation(conversationID)
	if err != nil {
		return nil, err
	}

	details := make([]database.ProcessDetail, 0)
	for _, rows := range detailsByMessage {
		details = append(details, rows...)
	}
	sort.SliceStable(details, func(i, j int) bool {
		if details[i].CreatedAt.Equal(details[j].CreatedAt) {
			return details[i].ID < details[j].ID
		}
		return details[i].CreatedAt.Before(details[j].CreatedAt)
	})
	vulnerabilities, err := db.ListVulnerabilities(500, 0, database.VulnerabilityListFilter{
		ConversationID: conversationID,
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(vulnerabilities, func(i, j int) bool {
		if vulnerabilities[i].CreatedAt.Equal(vulnerabilities[j].CreatedAt) {
			return vulnerabilities[i].ID < vulnerabilities[j].ID
		}
		return vulnerabilities[i].CreatedAt.Before(vulnerabilities[j].CreatedAt)
	})

	targetID := liveGraphID("target", conversationID)
	targetLabel := strings.TrimSpace(conversation.Title)
	if targetLabel == "" {
		targetLabel = "当前对话"
	}
	nodes := []Node{{
		ID:        targetID,
		Type:      "target",
		Label:     truncateLiveGraphText(targetLabel, 80),
		Metadata:  map[string]interface{}{"target": targetLabel, "status": "live"},
		RiskScore: 0,
	}}
	edges := make([]Edge, 0, len(details)*2+len(vulnerabilities)+4)
	edgeKeys := make(map[string]struct{})
	adjacency := make(map[string]map[string]struct{})
	addEdge := func(source, target, edgeType string) {
		appendLiveGraphEdge(&edges, adjacency, edgeKeys, conversationID, source, target, edgeType)
	}

	latestAssistant, conversationRunning := liveLatestAssistantState(conversation.Messages)
	hasProcessDetails := len(details) > 0
	hasToolEvent := false
	for _, detail := range details {
		if detail.EventType == "tool_call" || detail.EventType == "tool_result" {
			hasToolEvent = true
		}
	}
	analysisID := liveGraphID("phase", conversationID+"|analysis")
	analysisLabel := "分析准备中"
	analysisDescription := "正在建立执行上下文，等待首个可审计步骤。"
	if hasProcessDetails {
		analysisLabel = "建立分析上下文"
		analysisDescription = "已进入可审计的分析与执行规划阶段。"
	}
	analysisStatus := "running"
	if hasToolEvent || !conversationRunning {
		analysisStatus = "completed"
	}
	nodes = append(nodes, Node{
		ID:    analysisID,
		Type:  "action",
		Label: analysisLabel,
		Metadata: map[string]interface{}{
			"stage":       "analysis",
			"status":      analysisStatus,
			"description": analysisDescription,
		},
		RiskScore: 5,
	})
	addEdge(targetID, analysisID, "leads_to")

	matchedNodeIndexes := []bool{true, true}
	nodeIndexesByCallID := make(map[string][]int)
	lastMatchedNodeIndexByCallID := make(map[string]int)
	nodeIDByReference := make(map[string]string)
	toolNodeIDs := make([]string, 0)
	toolNameByNodeID := make(map[string]string)
	toolArgumentsByNodeID := make(map[string]string)
	toolResultsByNodeID := make(map[string]string)
	artifactProducers := make(map[string]string)
	pendingExecutionNodeIDs := make([]string, 0)
	knownExecutionIDs := make(map[string]struct{})
	frontierByLane := make(map[string][]string)
	iterationByLane := make(map[string]int)
	batchesByLane := make(map[string]*liveToolBatch)
	phaseCount := 0
	toolResultCount := 0

	laneFrontier := func(lane string) []string {
		if frontier := liveUniqueIDs(frontierByLane[lane]); len(frontier) > 0 {
			return frontier
		}
		return []string{analysisID}
	}
	finishBatch := func(lane string) {
		batch := batchesByLane[lane]
		if batch == nil {
			return
		}
		if nodeIDs := liveUniqueIDs(batch.nodeIDs); len(nodeIDs) > 0 {
			frontierByLane[lane] = nodeIDs
		}
		delete(batchesByLane, lane)
	}
	assignExecutionReferences := func(references []string) {
		for _, rawReference := range references {
			reference := liveNormalizeExecutionReference(rawReference)
			if reference == "" {
				continue
			}
			if _, known := knownExecutionIDs[reference]; known {
				continue
			}
			if existingNodeID := nodeIDByReference[reference]; existingNodeID != "" {
				knownExecutionIDs[reference] = struct{}{}
				continue
			}
			if len(pendingExecutionNodeIDs) == 0 {
				continue
			}
			nodeID := pendingExecutionNodeIDs[0]
			pendingExecutionNodeIDs = pendingExecutionNodeIDs[1:]
			index := liveNodeIndexByID(nodes, nodeID)
			if index < 0 {
				continue
			}
			nodes[index].ToolExecutionID = reference
			nodeIDByReference[reference] = nodeID
			knownExecutionIDs[reference] = struct{}{}
		}
	}

	for _, detail := range details {
		data := decodeLiveDetailData(detail.Data)
		lane := liveLaneKey(data)
		if detail.EventType == "planning" {
			assignExecutionReferences(liveDetailStringList(data, "mcpExecutionIds", "mcp_execution_ids"))
		}
		if detail.EventType == "finalization_check" {
			assignExecutionReferences(liveDetailStringList(data, "evidenceRefs", "evidence_refs"))
		}

		switch detail.EventType {
		case "iteration":
			finishBatch(lane)
			if iteration := liveDetailInt(data, "iteration"); iteration > 0 {
				iterationByLane[lane] = iteration
			}
			continue
		case "planning":
			finishBatch(lane)
			iteration := liveDetailInt(data, "iteration")
			if iteration <= 0 {
				iteration = iterationByLane[lane]
			}
			phaseCount++
			phaseID := liveGraphID("phase", conversationID+"|planning|"+detail.ID)
			phaseLabel := fmt.Sprintf("阶段 %d · 分析规划", phaseCount)
			if iteration > 0 {
				phaseLabel = fmt.Sprintf("第 %d 轮 · 分析规划", iteration)
			}
			nodes = append(nodes, Node{
				ID:    phaseID,
				Type:  "action",
				Label: phaseLabel,
				Metadata: map[string]interface{}{
					"stage":             "analysis",
					"status":            "completed",
					"iteration":         iteration,
					"run_id":            liveDetailString(data, "runId", "run_id"),
					"agent":             liveDetailString(data, "einoAgent", "agent"),
					"process_detail_id": detail.ID,
					"description":       "已记录本轮可审计的分析与规划阶段。",
					"created_at":        detail.CreatedAt,
				},
				RiskScore: 5,
			})
			matchedNodeIndexes = append(matchedNodeIndexes, true)
			for _, parentID := range laneFrontier(lane) {
				addEdge(parentID, phaseID, "leads_to")
			}
			frontierByLane[lane] = []string{phaseID}
			continue
		case "tool_calls_detected":
			finishBatch(lane)
			batchesByLane[lane] = &liveToolBatch{
				parents:  laneFrontier(lane),
				expected: liveDetailInt(data, "count", "total"),
			}
			continue
		case "tool_call", "tool_result":
		default:
			continue
		}

		callID := liveDetailString(data, "toolCallId", "tool_call_id")
		toolName := liveDetailString(data, "toolName", "tool_name")
		if toolName == "" {
			toolName = strings.TrimSpace(detail.Message)
		}
		if toolName == "" {
			toolName = "工具调用"
		}

		if detail.EventType == "tool_call" {
			batch := batchesByLane[lane]
			if batch == nil {
				batch = &liveToolBatch{parents: laneFrontier(lane)}
				batchesByLane[lane] = batch
			}
			nodeID := liveGraphID("action", conversationID+"|"+detail.ID)
			iteration := iterationByLane[lane]
			if dataIteration := liveDetailInt(data, "iteration"); dataIteration > 0 {
				iteration = dataIteration
			}
			argumentsText := liveToolArgumentsText(data)
			metadata := map[string]interface{}{
				"tool_name":         toolName,
				"tool_call_id":      callID,
				"process_detail_id": detail.ID,
				"status":            "running",
				"description":       truncateLiveGraphText(detail.Message, 240),
				"created_at":        detail.CreatedAt,
				"iteration":         iteration,
				"run_id":            liveDetailString(data, "runId", "run_id"),
				"agent":             liveDetailString(data, "einoAgent", "agent"),
			}
			executionID := liveDetailString(data, "executionId", "execution_id", "mcpExecutionId")
			nodes = append(nodes, Node{
				ID:              nodeID,
				Type:            "action",
				Label:           truncateLiveGraphText(toolName, 80),
				ToolExecutionID: executionID,
				Metadata:        metadata,
				RiskScore:       20,
			})
			index := len(nodes) - 1
			matchedNodeIndexes = append(matchedNodeIndexes, false)
			toolNodeIDs = append(toolNodeIDs, nodeID)
			toolNameByNodeID[nodeID] = toolName
			toolArgumentsByNodeID[nodeID] = argumentsText
			if callID != "" {
				nodeIndexesByCallID[callID] = append(nodeIndexesByCallID[callID], index)
				nodeIDByReference[callID] = nodeID
			}
			nodeIDByReference[detail.ID] = nodeID
			if executionID != "" {
				nodeIDByReference[executionID] = nodeID
				knownExecutionIDs[executionID] = struct{}{}
			} else {
				pendingExecutionNodeIDs = append(pendingExecutionNodeIDs, nodeID)
			}

			parentIDs := make([]string, 0)
			for _, reference := range liveDependencyReferences(data) {
				if parentID := nodeIDByReference[reference]; parentID != "" {
					parentIDs = append(parentIDs, parentID)
				}
			}
			if len(parentIDs) == 0 && argumentsText != "" {
				for artifact, producerID := range artifactProducers {
					if strings.Contains(argumentsText, artifact) {
						parentIDs = append(parentIDs, producerID)
					}
				}
			}
			if len(parentIDs) == 0 {
				parentIDs = append(parentIDs, batch.parents...)
			}
			if len(parentIDs) == 0 {
				parentIDs = append(parentIDs, analysisID)
			}
			for _, parentID := range liveUniqueIDs(parentIDs) {
				addEdge(parentID, nodeID, "leads_to")
			}

			batch.nodeIDs = append(batch.nodeIDs, nodeID)
			for _, artifact := range liveProducedArtifacts(toolName, argumentsText, "") {
				artifactProducers[artifact] = nodeID
			}
			expected := batch.expected
			if total := liveDetailInt(data, "total"); total > expected {
				expected = total
				batch.expected = total
			}
			indexInBatch := liveDetailInt(data, "index")
			if expected > 0 && (len(batch.nodeIDs) >= expected || indexInBatch >= expected) {
				finishBatch(lane)
			}
			continue
		}

		toolResultCount++
		index := matchLiveResultNode(nodes, matchedNodeIndexes, callID, toolName, nodeIndexesByCallID, lastMatchedNodeIndexByCallID)
		if index < 0 {
			nodeID := liveGraphID("action", conversationID+"|"+detail.ID)
			orphanExecutionID := liveDetailString(data, "executionId", "execution_id", "mcpExecutionId")
			nodes = append(nodes, Node{
				ID:              nodeID,
				Type:            "action",
				Label:           truncateLiveGraphText(toolName, 80),
				ToolExecutionID: orphanExecutionID,
				Metadata: map[string]interface{}{
					"tool_name":         toolName,
					"tool_call_id":      callID,
					"process_detail_id": detail.ID,
					"status":            "running",
					"description":       truncateLiveGraphText(detail.Message, 240),
					"created_at":        detail.CreatedAt,
				},
				RiskScore: 20,
			})
			index = len(nodes) - 1
			matchedNodeIndexes = append(matchedNodeIndexes, false)
			toolNodeIDs = append(toolNodeIDs, nodeID)
			toolNameByNodeID[nodeID] = toolName
			if callID != "" {
				nodeIDByReference[callID] = nodeID
			}
			if orphanExecutionID != "" {
				nodeIDByReference[orphanExecutionID] = nodeID
				knownExecutionIDs[orphanExecutionID] = struct{}{}
			} else {
				pendingExecutionNodeIDs = append(pendingExecutionNodeIDs, nodeID)
			}
			for _, parentID := range laneFrontier(lane) {
				addEdge(parentID, nodeID, "leads_to")
			}
			frontierByLane[lane] = []string{nodeID}
		}

		matchedNodeIndexes[index] = true
		nodeID := nodes[index].ID
		if callID != "" {
			lastMatchedNodeIndexByCallID[callID] = index
			nodeIDByReference[callID] = nodeID
		}
		status, riskScore := liveToolResultStatus(data)
		result := liveDetailString(data, "result", "output", "error", "resultPreview")
		if result == "" {
			result = detail.Message
		}
		nodes[index].RiskScore = riskScore
		nodes[index].Metadata["status"] = status
		nodes[index].Metadata["result"] = truncateLiveGraphText(result, 500)
		nodes[index].Metadata["result_process_detail_id"] = detail.ID
		toolResultsByNodeID[nodeID] = result
		if status == "completed" && strings.TrimSpace(result) != "" {
			nodes[index].Metadata["findings"] = []string{truncateLiveGraphText(result, 160)}
		} else {
			delete(nodes[index].Metadata, "findings")
		}
		if executionID := liveDetailString(data, "executionId", "execution_id", "mcpExecutionId"); executionID != "" {
			nodes[index].ToolExecutionID = executionID
			nodeIDByReference[executionID] = nodeID
			knownExecutionIDs[executionID] = struct{}{}
			pendingExecutionNodeIDs = liveRemoveID(pendingExecutionNodeIDs, nodeID)
		}
		for _, artifact := range liveProducedArtifacts(toolName, toolArgumentsByNodeID[nodeID], result) {
			artifactProducers[artifact] = nodeID
		}
	}

	for lane := range batchesByLane {
		finishBatch(lane)
	}

	var resultID string
	if toolResultCount > 0 {
		completedTools := 0
		failedTools := 0
		runningTools := 0
		for _, nodeID := range toolNodeIDs {
			index := liveNodeIndexByID(nodes, nodeID)
			if index < 0 {
				continue
			}
			status := strings.ToLower(strings.TrimSpace(fmt.Sprint(nodes[index].Metadata["status"])))
			switch status {
			case "completed":
				completedTools++
			case "failed", "blocked", "cancelled", "timeout":
				failedTools++
			default:
				runningTools++
			}
		}
		resultStatus := "completed"
		if runningTools > 0 {
			resultStatus = "running"
		}
		resultID = liveGraphID("phase", conversationID+"|results")
		nodes = append(nodes, Node{
			ID:    resultID,
			Type:  "action",
			Label: fmt.Sprintf("执行结果 · %d 项", toolResultCount),
			Metadata: map[string]interface{}{
				"stage":           "result",
				"status":          resultStatus,
				"completed_tools": completedTools,
				"failed_tools":    failedTools,
				"running_tools":   runningTools,
				"description":     "工具结果已进入确定性汇总，风险记录将继续追加到图中。",
			},
			RiskScore: 10,
		})
		for _, parentID := range liveLeafNodeIDs(nodes[:len(nodes)-1], adjacency) {
			addEdge(parentID, resultID, "leads_to")
		}
	}

	vulnerabilityNodeByID := make(map[string]string)
	for _, vulnerability := range vulnerabilities {
		if vulnerability == nil {
			continue
		}
		nodeID := liveGraphID("vulnerability", conversationID+"|"+vulnerability.ID)
		label := strings.TrimSpace(vulnerability.Title)
		if label == "" {
			label = "已确认风险"
		}
		nodes = append(nodes, Node{
			ID:        nodeID,
			Type:      "vulnerability",
			Label:     truncateLiveGraphText(label, 80),
			RiskScore: liveVulnerabilityRiskScore(vulnerability.Severity),
			Metadata: map[string]interface{}{
				"stage":            "finding",
				"status":           strings.TrimSpace(vulnerability.Status),
				"severity":         strings.TrimSpace(vulnerability.Severity),
				"target":           strings.TrimSpace(vulnerability.Target),
				"description":      truncateLiveGraphText(vulnerability.Description, 500),
				"vulnerability_id": vulnerability.ID,
				"created_at":       vulnerability.CreatedAt,
			},
		})
		vulnerabilityNodeByID[vulnerability.ID] = nodeID
		sourceID := liveVulnerabilitySource(
			vulnerability,
			toolNodeIDs,
			toolNameByNodeID,
			toolArgumentsByNodeID,
			toolResultsByNodeID,
		)
		if sourceID == "" {
			sourceID = resultID
		}
		if sourceID == "" {
			sourceID = analysisID
		}
		addEdge(sourceID, nodeID, "discovers")
	}

	var completionID string
	if latestAssistant != nil && !conversationRunning {
		completionStatus := "completed"
		completionLabel := "执行完成"
		for index := len(details) - 1; index >= 0; index-- {
			switch details[index].EventType {
			case "cancelled":
				completionStatus = "cancelled"
				completionLabel = "执行已终止"
			case "error":
				completionStatus = "failed"
				completionLabel = "执行失败"
			default:
				continue
			}
			break
		}
		completionID = liveGraphID("phase", conversationID+"|completion")
		nodes = append(nodes, Node{
			ID:    completionID,
			Type:  "action",
			Label: completionLabel,
			Metadata: map[string]interface{}{
				"stage":       "completion",
				"status":      completionStatus,
				"description": "本轮执行已结束，可使用 AI 归纳生成整理后的攻击链。",
			},
			RiskScore: 0,
		})
		completionParents := liveLeafNodeIDs(nodes[:len(nodes)-1], adjacency)
		for _, parentID := range completionParents {
			addEdge(parentID, completionID, "leads_to")
		}
	}

	outcome, finalizationData := liveConversationOutcome(details, vulnerabilities, conversationRunning)
	criticalPaths := make([]LiveCriticalPath, 0)
	criticalNodeIDs := make([]string, 0)
	criticalEdgeIDs := make([]string, 0)
	if outcome == "success" {
		anchorIDs := liveCriticalAnchorNodeIDs(
			finalizationData,
			vulnerabilities,
			vulnerabilityNodeByID,
			nodeIDByReference,
			toolNodeIDs,
			toolResultsByNodeID,
		)
		for index, anchorID := range anchorIDs {
			nodeIDs, edgeIDs := liveTraceCriticalPath(targetID, anchorID, completionID, nodes, edges)
			if len(nodeIDs) == 0 {
				continue
			}
			criticalPaths = append(criticalPaths, LiveCriticalPath{
				ID:       liveGraphID("critical_path", conversationID+"|"+anchorID),
				Label:    fmt.Sprintf("关键路径 %d", index+1),
				Evidence: "最终校验已通过，路径包含可验证的成功证据。",
				NodeIDs:  nodeIDs,
				EdgeIDs:  edgeIDs,
			})
			criticalNodeIDs = append(criticalNodeIDs, nodeIDs...)
			criticalEdgeIDs = append(criticalEdgeIDs, edgeIDs...)
		}
	}

	return &LiveChain{
		Nodes:           nodes,
		Edges:           edges,
		Revision:        liveChainRevision(details, latestAssistant, vulnerabilities),
		Mode:            "live",
		Running:         conversationRunning,
		Outcome:         outcome,
		CriticalNodeIDs: liveUniqueIDs(criticalNodeIDs),
		CriticalEdgeIDs: liveUniqueIDs(criticalEdgeIDs),
		CriticalPaths:   criticalPaths,
		GeneratedAt:     time.Now(),
	}, nil
}

func appendLiveGraphEdge(
	edges *[]Edge,
	adjacency map[string]map[string]struct{},
	edgeKeys map[string]struct{},
	conversationID, source, target, edgeType string,
) {
	source = strings.TrimSpace(source)
	target = strings.TrimSpace(target)
	if source == "" || target == "" || source == target {
		return
	}
	if edgeType == "" {
		edgeType = "leads_to"
	}
	key := source + "\x00" + target + "\x00" + edgeType
	if _, exists := edgeKeys[key]; exists {
		return
	}
	if liveGraphHasPath(adjacency, target, source, map[string]bool{}) {
		return
	}
	edgeKeys[key] = struct{}{}
	if adjacency[source] == nil {
		adjacency[source] = make(map[string]struct{})
	}
	adjacency[source][target] = struct{}{}
	*edges = append(*edges, Edge{
		ID:     liveGraphID("edge", conversationID+"|"+source+"|"+target+"|"+edgeType),
		Source: source,
		Target: target,
		Type:   edgeType,
		Weight: 1,
	})
}

func liveGraphHasPath(adjacency map[string]map[string]struct{}, current, target string, visited map[string]bool) bool {
	if current == target {
		return true
	}
	if visited[current] {
		return false
	}
	visited[current] = true
	for next := range adjacency[current] {
		if liveGraphHasPath(adjacency, next, target, visited) {
			return true
		}
	}
	return false
}

func liveLeafNodeIDs(nodes []Node, adjacency map[string]map[string]struct{}) []string {
	leaves := make([]string, 0)
	for _, node := range nodes {
		if len(adjacency[node.ID]) == 0 {
			leaves = append(leaves, node.ID)
		}
	}
	return liveUniqueIDs(leaves)
}

func liveUniqueIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, rawID := range ids {
		id := strings.TrimSpace(rawID)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func liveLaneKey(data map[string]interface{}) string {
	runID := liveDetailString(data, "runId", "run_id")
	agent := liveDetailString(data, "einoAgent", "agent", "agentName")
	if runID == "" && agent == "" {
		return "main"
	}
	return runID + "|" + agent
}

func liveDetailInt(data map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		value, exists := data[key]
		if !exists || value == nil {
			continue
		}
		switch typed := value.(type) {
		case int:
			return typed
		case int64:
			return int(typed)
		case float64:
			return int(typed)
		case json.Number:
			if parsed, err := typed.Int64(); err == nil {
				return int(parsed)
			}
		default:
			if parsed, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(value))); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func liveToolArgumentsText(data map[string]interface{}) string {
	if arguments, exists := data["argumentsObj"]; exists && arguments != nil {
		if encoded, err := json.Marshal(arguments); err == nil {
			return string(encoded)
		}
	}
	return liveDetailString(data, "arguments", "args", "input")
}

func liveDependencyReferences(data map[string]interface{}) []string {
	keys := []string{
		"parentToolCallId", "parent_tool_call_id",
		"sourceToolCallId", "source_tool_call_id",
		"dependsOn", "depends_on", "dependencies",
	}
	references := make([]string, 0)
	var collect func(interface{})
	collect = func(value interface{}) {
		switch typed := value.(type) {
		case string:
			for _, part := range strings.FieldsFunc(typed, func(r rune) bool {
				return r == ',' || r == ';' || r == '|' || r == ' '
			}) {
				if reference := strings.TrimSpace(part); reference != "" {
					references = append(references, reference)
				}
			}
		case []interface{}:
			for _, item := range typed {
				collect(item)
			}
		case []string:
			references = append(references, typed...)
		}
	}
	for _, key := range keys {
		if value, exists := data[key]; exists {
			collect(value)
		}
	}
	return liveUniqueIDs(references)
}

func liveProducedArtifacts(toolName, argumentsText, resultText string) []string {
	text := resultText
	name := strings.ToLower(strings.TrimSpace(toolName))
	if strings.Contains(name, "write") ||
		strings.Contains(name, "save") ||
		strings.Contains(name, "download") ||
		strings.Contains(name, "upload") {
		text += "\n" + argumentsText
	}
	if len(text) > 200000 {
		text = text[:200000]
	}
	artifacts := make([]string, 0)
	for _, token := range strings.Fields(text) {
		candidate := strings.Trim(token, "\"'`()[]{}<>,;")
		if len(candidate) < 8 || len(candidate) > 512 {
			continue
		}
		if strings.Contains(candidate, "://") || strings.HasPrefix(candidate, "/") {
			artifacts = append(artifacts, candidate)
		}
	}
	return liveUniqueIDs(artifacts)
}

func liveNodeIndexByID(nodes []Node, nodeID string) int {
	for index := range nodes {
		if nodes[index].ID == nodeID {
			return index
		}
	}
	return -1
}

func liveVulnerabilitySource(
	vulnerability *database.Vulnerability,
	toolNodeIDs []string,
	toolNameByNodeID, toolArgumentsByNodeID, toolResultsByNodeID map[string]string,
) string {
	if vulnerability == nil {
		return ""
	}
	needles := []string{
		strings.ToLower(strings.TrimSpace(vulnerability.ID)),
		strings.ToLower(strings.TrimSpace(vulnerability.Title)),
		strings.ToLower(strings.TrimSpace(vulnerability.Target)),
	}
	for index := len(toolNodeIDs) - 1; index >= 0; index-- {
		nodeID := toolNodeIDs[index]
		toolName := strings.ToLower(strings.TrimSpace(toolNameByNodeID[nodeID]))
		haystack := strings.ToLower(toolArgumentsByNodeID[nodeID] + "\n" + toolResultsByNodeID[nodeID])
		matched := false
		for _, needle := range needles {
			if len(needle) >= 4 && strings.Contains(haystack, needle) {
				matched = true
				break
			}
		}
		if matched || strings.Contains(toolName, "record_vulnerability") {
			return nodeID
		}
	}
	return ""
}

var liveFlagEvidencePattern = regexp.MustCompile(`(?i)(?:ctf|flag)\{[^}\r\n]{1,200}\}`)

func liveDetailStringList(data map[string]interface{}, keys ...string) []string {
	values := make([]string, 0)
	var collect func(interface{})
	collect = func(value interface{}) {
		switch typed := value.(type) {
		case string:
			if text := strings.TrimSpace(typed); text != "" {
				values = append(values, text)
			}
		case []interface{}:
			for _, item := range typed {
				collect(item)
			}
		case []string:
			for _, item := range typed {
				collect(item)
			}
		}
	}
	for _, key := range keys {
		if value, exists := data[key]; exists {
			collect(value)
		}
	}
	return liveUniqueIDs(values)
}

func liveNormalizeExecutionReference(reference string) string {
	reference = strings.TrimSpace(reference)
	for _, prefix := range []string{"mcp_execution:", "execution:"} {
		if strings.HasPrefix(strings.ToLower(reference), prefix) {
			return strings.TrimSpace(reference[len(prefix):])
		}
	}
	return reference
}

func liveRemoveID(ids []string, target string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != target {
			out = append(out, id)
		}
	}
	return out
}

func liveConversationOutcome(
	details []database.ProcessDetail,
	vulnerabilities []*database.Vulnerability,
	running bool,
) (string, map[string]interface{}) {
	if running {
		return "running", nil
	}
	for index := len(details) - 1; index >= 0; index-- {
		detail := details[index]
		switch detail.EventType {
		case "finalization_check":
			data := decodeLiveDetailData(detail.Data)
			finalized, _ := liveDetailBool(data, "finalized")
			verified, _ := liveDetailBool(data, "evidenceVerified")
			status := strings.ToLower(liveDetailString(data, "status"))
			if finalized && verified && (status == "" || status == "completed" || status == "success") {
				return "success", data
			}
		case "error", "cancelled":
			return "failed", nil
		}
	}
	for _, vulnerability := range vulnerabilities {
		if vulnerability == nil {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(vulnerability.Status))
		if status != "false_positive" && status != "rejected" {
			return "success", nil
		}
	}
	return "completed", nil
}

func liveCriticalAnchorNodeIDs(
	finalizationData map[string]interface{},
	vulnerabilities []*database.Vulnerability,
	vulnerabilityNodeByID, nodeIDByReference map[string]string,
	toolNodeIDs []string,
	toolResultsByNodeID map[string]string,
) []string {
	anchors := make([]string, 0)
	evidenceNodeIDs := make([]string, 0)
	for _, rawReference := range liveDetailStringList(finalizationData, "evidenceRefs", "evidence_refs") {
		reference := liveNormalizeExecutionReference(rawReference)
		if nodeID := nodeIDByReference[reference]; nodeID != "" {
			evidenceNodeIDs = append(evidenceNodeIDs, nodeID)
		}
	}

	finalText := liveDetailString(finalizationData, "finalText", "final_text")
	evidenceTerms := liveFlagEvidencePattern.FindAllString(finalText, -1)
	for _, nodeID := range liveUniqueIDs(evidenceNodeIDs) {
		result := toolResultsByNodeID[nodeID]
		if liveResultContainsSuccessEvidence(result, evidenceTerms) {
			anchors = append(anchors, nodeID)
		}
	}
	if len(anchors) == 0 && len(evidenceNodeIDs) > 0 {
		anchors = append(anchors, evidenceNodeIDs[len(evidenceNodeIDs)-1])
	}

	for _, vulnerability := range vulnerabilities {
		if vulnerability == nil {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(vulnerability.Status))
		if status == "false_positive" || status == "rejected" {
			continue
		}
		if nodeID := vulnerabilityNodeByID[vulnerability.ID]; nodeID != "" {
			anchors = append(anchors, nodeID)
		}
	}
	if len(anchors) == 0 {
		for index := len(toolNodeIDs) - 1; index >= 0; index-- {
			nodeID := toolNodeIDs[index]
			if liveResultContainsSuccessEvidence(toolResultsByNodeID[nodeID], evidenceTerms) {
				anchors = append(anchors, nodeID)
				break
			}
		}
	}
	return liveUniqueIDs(anchors)
}

func liveResultContainsSuccessEvidence(result string, evidenceTerms []string) bool {
	lowerResult := strings.ToLower(result)
	for _, term := range evidenceTerms {
		if term != "" && strings.Contains(lowerResult, strings.ToLower(term)) {
			return true
		}
	}
	if liveFlagEvidencePattern.MatchString(result) {
		return true
	}
	for _, marker := range []string{
		"login successful",
		"authentication bypassed",
		"漏洞已成功记录",
		"uid=0(",
		"uid=33(",
	} {
		if strings.Contains(lowerResult, marker) {
			return true
		}
	}
	return false
}

func liveTraceCriticalPath(
	targetID, anchorID, completionID string,
	nodes []Node,
	edges []Edge,
) ([]string, []string) {
	if anchorID == "" {
		return nil, nil
	}
	incoming := make(map[string][]Edge)
	outgoing := make(map[string][]Edge)
	for _, edge := range edges {
		incoming[edge.Target] = append(incoming[edge.Target], edge)
		outgoing[edge.Source] = append(outgoing[edge.Source], edge)
	}
	nodeSet := map[string]bool{anchorID: true}
	edgeSet := make(map[string]bool)
	var walkIncoming func(string)
	walkIncoming = func(nodeID string) {
		for _, edge := range incoming[nodeID] {
			if edgeSet[edge.ID] {
				continue
			}
			edgeSet[edge.ID] = true
			nodeSet[edge.Source] = true
			walkIncoming(edge.Source)
		}
	}
	walkIncoming(anchorID)
	if targetID != "" {
		nodeSet[targetID] = true
	}

	if completionID != "" && anchorID != completionID {
		type pathStep struct {
			nodeID string
			edges  []Edge
		}
		queue := []pathStep{{nodeID: anchorID}}
		visited := map[string]bool{anchorID: true}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			if current.nodeID == completionID {
				for _, edge := range current.edges {
					edgeSet[edge.ID] = true
					nodeSet[edge.Source] = true
					nodeSet[edge.Target] = true
				}
				break
			}
			for _, edge := range outgoing[current.nodeID] {
				if visited[edge.Target] {
					continue
				}
				visited[edge.Target] = true
				nextEdges := append(append([]Edge(nil), current.edges...), edge)
				queue = append(queue, pathStep{nodeID: edge.Target, edges: nextEdges})
			}
		}
	}

	nodeIDs := make([]string, 0, len(nodeSet))
	for _, node := range nodes {
		if nodeSet[node.ID] {
			nodeIDs = append(nodeIDs, node.ID)
		}
	}
	edgeIDs := make([]string, 0, len(edgeSet))
	for _, edge := range edges {
		if edgeSet[edge.ID] {
			edgeIDs = append(edgeIDs, edge.ID)
		}
	}
	return nodeIDs, edgeIDs
}

func liveLatestAssistantState(messages []database.Message) (*database.Message, bool) {
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].Role != "assistant" {
			continue
		}
		content := strings.TrimSpace(messages[index].Content)
		running := content == "" || content == "处理中..." || content == "Processing..."
		return &messages[index], running
	}
	return nil, true
}

func liveVulnerabilityRiskScore(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 55
	case "low":
		return 30
	case "info":
		return 10
	default:
		return 40
	}
}

func liveChainRevision(
	details []database.ProcessDetail,
	latestAssistant *database.Message,
	vulnerabilities []*database.Vulnerability,
) string {
	parts := []string{fmt.Sprintf("details:%d", len(details))}
	if len(details) > 0 {
		parts = append(parts, details[len(details)-1].ID)
	}
	if latestAssistant != nil {
		parts = append(parts,
			latestAssistant.ID,
			latestAssistant.UpdatedAt.UTC().Format(time.RFC3339Nano),
			latestAssistant.Content,
		)
	}
	for _, vulnerability := range vulnerabilities {
		if vulnerability == nil {
			continue
		}
		parts = append(parts,
			vulnerability.ID,
			vulnerability.UpdatedAt.UTC().Format(time.RFC3339Nano),
			vulnerability.Status,
		)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:8])
}

func decodeLiveDetailData(raw string) map[string]interface{} {
	out := map[string]interface{}{}
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func liveDetailString(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := data[key]; ok && value != nil {
			text := strings.TrimSpace(fmt.Sprint(value))
			if text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}

func liveDetailBool(data map[string]interface{}, key string) (bool, bool) {
	value, ok := data[key]
	if !ok {
		return false, false
	}
	if result, ok := value.(bool); ok {
		return result, true
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if strings.EqualFold(text, "true") {
		return true, true
	}
	if strings.EqualFold(text, "false") {
		return false, true
	}
	return false, false
}

func matchLiveResultNode(
	nodes []Node,
	matched []bool,
	callID, toolName string,
	nodeIndexesByCallID map[string][]int,
	lastMatchedNodeIndexByCallID map[string]int,
) int {
	if callID != "" {
		queue := nodeIndexesByCallID[callID]
		for len(queue) > 0 {
			candidate := queue[0]
			queue = queue[1:]
			if candidate > 0 && candidate < len(matched) && !matched[candidate] {
				nodeIndexesByCallID[callID] = queue
				return candidate
			}
		}
		nodeIndexesByCallID[callID] = queue
		if previous, ok := lastMatchedNodeIndexByCallID[callID]; ok {
			return previous
		}
	}
	if toolName != "" {
		for index := 1; index < len(nodes) && index < len(matched); index++ {
			if !matched[index] && strings.EqualFold(liveNodeToolName(nodes[index]), toolName) {
				return index
			}
		}
	}
	return -1
}

func liveNodeToolName(node Node) string {
	if node.Metadata != nil {
		if value := strings.TrimSpace(fmt.Sprint(node.Metadata["tool_name"])); value != "" && value != "<nil>" {
			return value
		}
	}
	return strings.TrimSpace(node.Label)
}

func liveToolResultStatus(data map[string]interface{}) (string, int) {
	status := strings.ToLower(liveDetailString(data, "status"))
	if blocked, _ := liveDetailBool(data, "blocked"); blocked || status == "blocked" {
		return "blocked", 10
	}
	switch status {
	case "background_running", "running", "pending":
		return "running", 20
	case "cancelled", "canceled":
		return "cancelled", 15
	case "timeout":
		return "timeout", 15
	case "failed", "error":
		return "failed", 15
	case "completed", "success", "succeeded":
		return "completed", 35
	}
	if success, ok := liveDetailBool(data, "success"); ok {
		if success {
			return "completed", 35
		}
		return "failed", 15
	}
	if isError, ok := liveDetailBool(data, "isError"); ok && isError {
		return "failed", 15
	}
	return "completed", 35
}

func liveGraphID(prefix, value string) string {
	sum := sha256.Sum256([]byte(value))
	return prefix + "_" + hex.EncodeToString(sum[:8])
}

func truncateLiveGraphText(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	if maxRunes <= 0 || utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxRunes]) + "…"
}
