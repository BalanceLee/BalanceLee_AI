package beliefpath

import (
	"fmt"
	"math"
	"strings"
)

type ViewNode struct {
	ID              string
	Type            string
	Label           string
	ToolExecutionID string
	Metadata        map[string]interface{}
	RiskScore       int
}

type ViewEdge struct {
	ID     string
	Source string
	Target string
	Type   string
	Weight int
}

// OverlaySnapshot merges planner state into an existing execution graph.
// Action nodes are reused by tool_call_id or execution_id to avoid rendering
// the same tool invocation twice.
func OverlaySnapshot(
	baseNodes []ViewNode,
	baseEdges []ViewEdge,
	snapshot *Snapshot,
) ([]ViewNode, []ViewEdge) {
	if snapshot == nil || snapshot.Mode == ModeOff {
		return baseNodes, baseEdges
	}
	nodes := append([]ViewNode(nil), baseNodes...)
	edges := append([]ViewEdge(nil), baseEdges...)
	existingIDs := make(map[string]struct{}, len(nodes))
	toolCallNodes := make(map[string]string)
	executionNodes := make(map[string]string)
	for index := range nodes {
		node := &nodes[index]
		existingIDs[node.ID] = struct{}{}
		node.Metadata = nonNilMap(node.Metadata)
		if value := strings.TrimSpace(fmt.Sprint(node.Metadata["tool_call_id"])); value != "" && value != "<nil>" {
			toolCallNodes[value] = node.ID
		}
		if value := strings.TrimSpace(node.ToolExecutionID); value != "" {
			executionNodes[value] = node.ID
		}
	}

	mappedIDs := make(map[string]string, len(snapshot.Nodes))
	for _, plannerNode := range snapshot.Nodes {
		mappedID := ""
		if plannerNode.Kind == NodeAction {
			callID := strings.TrimSpace(fmt.Sprint(plannerNode.Metadata["tool_call_id"]))
			executionID := strings.TrimSpace(fmt.Sprint(plannerNode.Metadata["execution_id"]))
			mappedID = toolCallNodes[callID]
			if mappedID == "" {
				mappedID = executionNodes[executionID]
			}
			if mappedID != "" {
				if index := viewNodeIndex(nodes, mappedID); index >= 0 {
					enrichViewNode(&nodes[index], plannerNode)
				}
			}
		}
		if mappedID == "" {
			mappedID = "bp-" + plannerNode.ID
			if _, exists := existingIDs[mappedID]; !exists {
				nodes = append(nodes, ViewNode{
					ID:        mappedID,
					Type:      viewNodeType(plannerNode.Kind),
					Label:     plannerNode.Label,
					Metadata:  plannerNodeMetadata(plannerNode),
					RiskScore: plannerRiskScore(plannerNode),
				})
				existingIDs[mappedID] = struct{}{}
			}
		}
		mappedIDs[plannerNode.ID] = mappedID
	}

	edgeKeys := make(map[string]struct{}, len(edges)+len(snapshot.Edges))
	for _, edge := range edges {
		edgeKeys[edge.Source+"\x00"+edge.Target+"\x00"+edge.Type] = struct{}{}
	}
	for _, plannerEdge := range snapshot.Edges {
		source := mappedIDs[plannerEdge.SourceID]
		target := mappedIDs[plannerEdge.TargetID]
		appendViewEdge(
			&edges,
			edgeKeys,
			"bp-"+plannerEdge.ID,
			source,
			target,
			viewEdgeType(plannerEdge.Relation),
			plannerEdge.Confidence,
		)
	}
	for _, hyperedge := range snapshot.Hyperedges {
		hyperNodeID := "bp-h-" + hyperedge.ID
		if _, exists := existingIDs[hyperNodeID]; !exists {
			nodes = append(nodes, ViewNode{
				ID:    hyperNodeID,
				Type:  "action",
				Label: strings.ToUpper(hyperedge.Kind),
				Metadata: map[string]interface{}{
					"beliefpath":   true,
					"planner_kind": "hyperedge",
					"hyper_kind":   strings.ToUpper(hyperedge.Kind),
					"confidence":   hyperedge.Confidence,
					"status":       "structural",
				},
				RiskScore: 0,
			})
			existingIDs[hyperNodeID] = struct{}{}
		}
		for _, memberID := range hyperedge.MemberIDs {
			appendViewEdge(
				&edges,
				edgeKeys,
				"bp-hm-"+hyperedge.ID+"-"+memberID,
				mappedIDs[memberID],
				hyperNodeID,
				"depends_on",
				hyperedge.Confidence,
			)
		}
		appendViewEdge(
			&edges,
			edgeKeys,
			"bp-ht-"+hyperedge.ID,
			hyperNodeID,
			mappedIDs[hyperedge.TargetID],
			"enables",
			hyperedge.Confidence,
		)
	}
	return nodes, edges
}

func appendViewEdge(
	edges *[]ViewEdge,
	edgeKeys map[string]struct{},
	id, source, target, edgeType string,
	confidence float64,
) {
	if source == "" || target == "" || source == target {
		return
	}
	key := source + "\x00" + target + "\x00" + edgeType
	if _, exists := edgeKeys[key]; exists {
		return
	}
	edgeKeys[key] = struct{}{}
	*edges = append(*edges, ViewEdge{
		ID:     id,
		Source: source,
		Target: target,
		Type:   edgeType,
		Weight: int(math.Round(math.Max(1, confidence*100))),
	})
}

func enrichViewNode(node *ViewNode, plannerNode Node) {
	if node == nil {
		return
	}
	node.Metadata = nonNilMap(node.Metadata)
	node.Metadata["beliefpath"] = true
	node.Metadata["planner_kind"] = plannerNode.Kind
	node.Metadata["planner_state"] = plannerNode.State
	node.Metadata["confidence"] = plannerNode.Confidence
	node.Metadata["value"] = plannerNode.Value
	node.Metadata["repeat_count"] = plannerNode.RepeatCount
}

func plannerNodeMetadata(node Node) map[string]interface{} {
	metadata := map[string]interface{}{
		"beliefpath":              true,
		"planner_kind":            node.Kind,
		"planner_state":           node.State,
		"confidence":              node.Confidence,
		"value":                   node.Value,
		"prior":                   node.Prior,
		"visits":                  node.Visits,
		"repeat_count":            node.RepeatCount,
		"cooldown_until_revision": node.CooldownUntilRevision,
	}
	for key, value := range node.Metadata {
		metadata[key] = value
	}
	return metadata
}

func viewNodeType(kind string) string {
	switch kind {
	case NodeGoal:
		return "target"
	case NodeFact, NodeEvidence:
		return "result"
	default:
		return "action"
	}
}

func viewEdgeType(relation string) string {
	switch relation {
	case "requires":
		return "depends_on"
	case "supports", "produces", "establishes":
		return "enables"
	default:
		return "leads_to"
	}
}

func plannerRiskScore(node Node) int {
	switch node.State {
	case StatePrunedHard, StateBlockedPolicy:
		return 90
	case StateSuspended, StateCooling:
		return 55
	case StateSolved:
		return 10
	default:
		return 25
	}
}

func viewNodeIndex(nodes []ViewNode, id string) int {
	for index := range nodes {
		if nodes[index].ID == id {
			return index
		}
	}
	return -1
}
