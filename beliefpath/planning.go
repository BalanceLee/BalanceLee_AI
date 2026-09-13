package beliefpath

import (
	"context"
	"math"
	"math/rand"
	"sort"
	"strings"
	"unicode"
)

const toolFeatureDimensions = 8

var intentTemplates = []Intent{
	{
		Key:              "reconnaissance",
		Label:            "目标与服务侦察",
		Objective:        "识别目标、开放服务、技术栈和可达攻击面",
		Phase:            "recon",
		Prerequisites:    []string{"target_scope"},
		ExpectedEvidence: []string{"host", "port", "service", "technology"},
		Capabilities:     []string{"scan", "nmap", "subdomain", "http", "dns", "asset", "recon"},
		Prior:            0.82,
	},
	{
		Key:              "surface_enumeration",
		Label:            "应用与接口枚举",
		Objective:        "枚举路径、参数、接口、页面和潜在输入面",
		Phase:            "enumeration",
		Prerequisites:    []string{"target_discovered"},
		ExpectedEvidence: []string{"url", "endpoint", "parameter", "api"},
		Capabilities:     []string{"dir", "ffuf", "ferox", "http", "crawl", "gau", "wayback", "api"},
		Prior:            0.74,
	},
	{
		Key:              "vulnerability_validation",
		Label:            "漏洞验证",
		Objective:        "使用低破坏性证据验证候选漏洞并排除误报",
		Phase:            "validation",
		Prerequisites:    []string{"target_discovered", "attack_surface_mapped"},
		ExpectedEvidence: []string{"vulnerability", "proof", "response", "finding"},
		Capabilities:     []string{"nuclei", "nikto", "sql", "xss", "jwt", "scanner", "vulnerability"},
		Prior:            0.68,
	},
	{
		Key:              "credential_access",
		Label:            "认证与凭据路径",
		Objective:        "验证认证绕过、凭据复用、会话和访问控制路径",
		Phase:            "credential",
		Prerequisites:    []string{"attack_surface_mapped"},
		ExpectedEvidence: []string{"credential", "session", "login", "token"},
		Capabilities:     []string{"auth", "login", "credential", "hydra", "jwt", "session"},
		Prior:            0.58,
	},
	{
		Key:              "controlled_exploitation",
		Label:            "受控利用",
		Objective:        "在授权与安全约束内验证可利用性并获取可审计证据",
		Phase:            "exploit",
		Prerequisites:    []string{"target_discovered", "confirmed_vector"},
		ExpectedEvidence: []string{"execution", "shell", "impact", "flag"},
		Capabilities:     []string{"exploit", "execute", "metasploit", "payload", "webshell", "c2"},
		Prior:            0.48,
	},
	{
		Key:              "post_exploitation",
		Label:            "权限与影响验证",
		Objective:        "确认当前权限、可达资源和目标影响，避免无目的扩张",
		Phase:            "post_exploit",
		Prerequisites:    []string{"target_discovered", "foothold"},
		ExpectedEvidence: []string{"identity", "privilege", "asset", "reachability"},
		Capabilities:     []string{"whoami", "privilege", "post", "session", "c2", "webshell"},
		Prior:            0.38,
	},
	{
		Key:              "objective_verification",
		Label:            "目标终态验证",
		Objective:        "复核成功条件并绑定最终结论与执行证据",
		Phase:            "verify",
		Prerequisites:    []string{"objective_evidence"},
		ExpectedEvidence: []string{"terminal_evidence", "confirmed finding", "goal"},
		Capabilities:     []string{"verify", "read", "get", "query", "record", "vulnerability"},
		Prior:            0.32,
	},
}

type toolBanditStat struct {
	ToolName      string
	Pulls         int64
	RewardSum     float64
	ADiag         []float64
	B             []float64
	Successes     int64
	Failures      int64
	AvgDurationMS float64
}

func newToolBanditStat(toolName string, dimensions int) toolBanditStat {
	stat := toolBanditStat{ToolName: toolName}
	stat.ensureDimensions(dimensions)
	return stat
}

func (s *toolBanditStat) ensureDimensions(dimensions int) {
	if dimensions <= 0 {
		dimensions = toolFeatureDimensions
	}
	if len(s.ADiag) != dimensions {
		s.ADiag = make([]float64, dimensions)
		for i := range s.ADiag {
			s.ADiag[i] = 1
		}
	}
	if len(s.B) != dimensions {
		s.B = make([]float64, dimensions)
	}
	for i := range s.ADiag {
		if s.ADiag[i] <= 0 {
			s.ADiag[i] = 1
		}
	}
}

func (s toolBanditStat) score(features []float64, alpha float64) float64 {
	if alpha <= 0 {
		alpha = 0.65
	}
	exploit := 0.0
	uncertainty := 0.0
	for i, feature := range features {
		if i >= len(s.ADiag) || i >= len(s.B) {
			break
		}
		exploit += (s.B[i] / s.ADiag[i]) * feature
		uncertainty += feature * feature / s.ADiag[i]
	}
	return exploit + alpha*math.Sqrt(math.Max(0, uncertainty))
}

func (s *toolBanditStat) update(features []float64, reward float64, durationMS int64) {
	s.ensureDimensions(len(features))
	s.Pulls++
	s.RewardSum += reward
	if reward > 0 {
		s.Successes++
	} else if reward < 0 {
		s.Failures++
	}
	for i, feature := range features {
		s.ADiag[i] += feature * feature
		s.B[i] += reward * feature
	}
	if durationMS > 0 {
		if s.AvgDurationMS <= 0 {
			s.AvgDurationMS = float64(durationMS)
		} else {
			s.AvgDurationMS = 0.8*s.AvgDurationMS + 0.2*float64(durationMS)
		}
	}
}

func generateIntents(conversationID, goal string, existing []Node, maxIntents int) []Intent {
	existingByKey := make(map[string]Node, len(existing))
	for _, node := range existing {
		existingByKey[node.CanonicalKey] = node
	}
	scope := stableID("intent-scope", strings.TrimSpace(goal))[:12]
	lowerGoal := strings.ToLower(goal)
	intents := make([]Intent, 0, len(intentTemplates))
	for _, template := range intentTemplates {
		intent := template
		intent.Key = scope + ":" + template.Key
		intent.ID = stableID("intent", conversationID, intent.Key)
		intent.State = StateActive
		intent.Alpha = 1
		intent.Beta = 1
		if node, ok := existingByKey["intent:"+intent.Key]; ok {
			intent = intentFromNode(node)
			intent.Objective = template.Objective
			intent.Phase = template.Phase
			intent.Prerequisites = append([]string(nil), template.Prerequisites...)
			intent.ExpectedEvidence = append([]string(nil), template.ExpectedEvidence...)
			intent.Capabilities = append([]string(nil), template.Capabilities...)
		}
		for _, term := range append(append([]string{}, template.Capabilities...), template.ExpectedEvidence...) {
			if strings.Contains(lowerGoal, strings.ToLower(term)) {
				intent.Prior = clamp01(intent.Prior + 0.08)
			}
		}
		intents = append(intents, intent)
	}
	sort.SliceStable(intents, func(i, j int) bool {
		return intents[i].Prior > intents[j].Prior
	})
	if maxIntents > 0 && len(intents) > maxIntents {
		verify := intents[len(intents)-1]
		for _, intent := range intents {
			if intent.Phase == "verify" {
				verify = intent
				break
			}
		}
		intents = append(append([]Intent(nil), intents[:maxIntents-1]...), verify)
	}
	return intents
}

func intentFromNode(node Node) Intent {
	intent := Intent{
		ID:            node.ID,
		Key:           strings.TrimPrefix(node.CanonicalKey, "intent:"),
		Label:         node.Label,
		State:         node.State,
		Prior:         node.Prior,
		Alpha:         node.Alpha,
		Beta:          node.Beta,
		Visits:        node.Visits,
		RepeatCount:   node.RepeatCount,
		CooldownUntil: node.CooldownUntilRevision,
	}
	if node.Metadata != nil {
		intent.Objective = stringValue(node.Metadata["objective"])
		intent.Phase = stringValue(node.Metadata["phase"])
		intent.ExpectedEvidence = stringSliceValue(node.Metadata["expected_evidence"])
		intent.Capabilities = stringSliceValue(node.Metadata["capabilities"])
		intent.Prerequisites = stringSliceValue(node.Metadata["prerequisites"])
	}
	return intent
}

func nodeFromIntent(conversationID string, intent Intent) Node {
	return Node{
		ID:                    intent.ID,
		ConversationID:        conversationID,
		Kind:                  NodeIntent,
		CanonicalKey:          "intent:" + intent.Key,
		Label:                 intent.Label,
		State:                 intent.State,
		Confidence:            posteriorMean(intent.Alpha, intent.Beta),
		Prior:                 intent.Prior,
		Value:                 posteriorMean(intent.Alpha, intent.Beta),
		Alpha:                 intent.Alpha,
		Beta:                  intent.Beta,
		Visits:                intent.Visits,
		Successes:             int64(math.Max(0, intent.Alpha-1)),
		Failures:              int64(math.Max(0, intent.Beta-1)),
		RepeatCount:           intent.RepeatCount,
		CooldownUntilRevision: intent.CooldownUntil,
		Metadata: map[string]interface{}{
			"objective":         intent.Objective,
			"phase":             intent.Phase,
			"prerequisites":     intent.Prerequisites,
			"expected_evidence": intent.ExpectedEvidence,
			"capabilities":      intent.Capabilities,
		},
	}
}

func scoreIntents(cfg Config, intents []Intent, revision int64) []CandidateScore {
	cfg = cfg.Effective()
	totalVisits := int64(1)
	for _, intent := range intents {
		totalVisits += intent.Visits
	}
	out := make([]CandidateScore, 0, len(intents))
	for _, intent := range intents {
		state := intent.State
		if state == StateCooling && revision >= intent.CooldownUntil {
			state = StateActive
		}
		mean := posteriorMean(intent.Alpha, intent.Beta)
		exploration := cfg.Exploration * intent.Prior *
			math.Sqrt(float64(totalVisits)) / float64(1+intent.Visits)
		infoGain := 1 / math.Sqrt(float64(intent.Alpha+intent.Beta))
		repeatPenalty := cfg.RepeatWeight * float64(intent.RepeatCount)
		risk := intentRisk(intent)
		cost := intentCost(intent)
		score := mean + exploration + cfg.InformationGainWeight*infoGain -
			cfg.CostWeight*cost - cfg.RiskWeight*risk - repeatPenalty
		reason := ""
		switch state {
		case StatePrunedHard, StateBlockedPolicy, StateSolved:
			score = math.Inf(-1)
			reason = state
		case StateCooling, StateSuspended:
			score -= 2
			reason = state
		}
		out = append(out, CandidateScore{
			IntentID:        intent.ID,
			IntentKey:       intent.Key,
			Label:           intent.Label,
			Score:           score,
			MeanSuccess:     mean,
			Exploration:     exploration,
			InformationGain: infoGain,
			Cost:            cost,
			Risk:            risk,
			RepeatPenalty:   repeatPenalty,
			State:           state,
			Reason:          reason,
		})
	}
	if cfg.UsesPUCT() {
		applyBudgetedPUCT(out, intents, cfg, revision)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].IntentKey < out[j].IntentKey
		}
		return out[i].Score > out[j].Score
	})
	return out
}

// applyBudgetedPUCT performs bounded virtual simulations over high-level intents.
// It never invokes a real tool or an LLM during rollout.
func applyBudgetedPUCT(scores []CandidateScore, intents []Intent, cfg Config, revision int64) {
	if len(scores) == 0 {
		return
	}
	indexByID := make(map[string]int, len(scores))
	for i := range scores {
		indexByID[scores[i].IntentID] = i
	}
	visits := make([]int, len(scores))
	values := make([]float64, len(scores))
	seed := cfg.RandomSeed + revision
	rng := rand.New(rand.NewSource(seed))
	for simulation := 0; simulation < cfg.PUCTSimulations; simulation++ {
		total := 1
		for _, count := range visits {
			total += count
		}
		best := -1
		bestScore := math.Inf(-1)
		for _, intent := range intents {
			index, ok := indexByID[intent.ID]
			if !ok || math.IsInf(scores[index].Score, -1) {
				continue
			}
			q := 0.0
			if visits[index] > 0 {
				q = values[index] / float64(visits[index])
			}
			puct := q + cfg.Exploration*intent.Prior*
				math.Sqrt(float64(total))/float64(1+visits[index])
			if puct > bestScore {
				bestScore = puct
				best = index
			}
		}
		if best < 0 {
			break
		}
		virtualValue := scores[best].MeanSuccess +
			cfg.InformationGainWeight*scores[best].InformationGain -
			cfg.CostWeight*scores[best].Cost -
			cfg.RiskWeight*scores[best].Risk -
			scores[best].RepeatPenalty
		virtualValue += (rng.Float64() - 0.5) * 0.02
		visits[best]++
		values[best] += virtualValue
	}
	for i := range scores {
		if visits[i] == 0 || math.IsInf(scores[i].Score, -1) {
			continue
		}
		scores[i].Score = values[i]/float64(visits[i]) +
			cfg.ExplorationFloor*math.Log1p(float64(visits[i]))
	}
}

func (s *Service) rankTools(
	ctx context.Context,
	goal string,
	intent Intent,
	tools []ToolDescriptor,
) ([]ToolScore, error) {
	cfg := s.Config()
	queryTokens := tokenize(strings.Join([]string{
		goal, intent.Label, intent.Objective,
		strings.Join(intent.Capabilities, " "),
		strings.Join(intent.ExpectedEvidence, " "),
	}, " "))
	stats, err := s.store.loadToolStats(ctx, toolFeatureDimensions)
	if err != nil {
		return nil, err
	}
	scored := make([]ToolScore, 0, len(tools))
	for _, item := range tools {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		stat, ok := stats[strings.ToLower(name)]
		if !ok {
			stat = newToolBanditStat(name, toolFeatureDimensions)
		}
		features := toolFeatures(queryTokens, intent, item, stat)
		heuristic := 1.2*features[1] + 1.4*features[2] +
			0.5*features[3] + 0.25*features[5] -
			0.4*features[6] - 0.35*features[7]
		score := heuristic
		if cfg.UsesRouter() {
			score += stat.score(features, 0.65)
		}
		scored = append(scored, ToolScore{
			Name:        name,
			Score:       score,
			Features:    features,
			Explanation: toolScoreExplanation(features, stat),
		})
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].Score == scored[j].Score {
			return scored[i].Name < scored[j].Name
		}
		return scored[i].Score > scored[j].Score
	})
	if len(scored) > cfg.TopKTools {
		scored = scored[:cfg.TopKTools]
	}
	return scored, nil
}

func toolFeatures(queryTokens map[string]struct{}, intent Intent, tool ToolDescriptor, stat toolBanditStat) []float64 {
	nameTokens := tokenize(tool.Name)
	descriptionTokens := tokenize(tool.Description)
	nameOverlap := overlapRatio(queryTokens, nameTokens)
	descriptionOverlap := overlapRatio(queryTokens, descriptionTokens)
	capabilityMatch := 0.0
	lower := strings.ToLower(tool.Name + " " + tool.Description)
	for _, capability := range intent.Capabilities {
		if strings.Contains(lower, strings.ToLower(capability)) {
			capabilityMatch += 1
		}
	}
	if len(intent.Capabilities) > 0 {
		capabilityMatch /= float64(len(intent.Capabilities))
	}
	successMean := 0.5
	if stat.Successes+stat.Failures > 0 {
		successMean = float64(stat.Successes+1) / float64(stat.Successes+stat.Failures+2)
	}
	latencyScore := 1.0
	if stat.AvgDurationMS > 0 {
		latencyScore = 1 / (1 + math.Log1p(stat.AvgDurationMS/1000))
	}
	novelty := 1 / math.Sqrt(float64(stat.Pulls+1))
	risk := inferredToolRisk(lower)
	return []float64{
		1,
		nameOverlap,
		descriptionOverlap,
		capabilityMatch,
		successMean,
		latencyScore,
		novelty,
		risk,
	}
}

func toolScoreExplanation(features []float64, stat toolBanditStat) string {
	if len(features) < toolFeatureDimensions {
		return "insufficient features"
	}
	return "capability match, evidence history, latency, exploration and risk"
}

func tokenize(value string) map[string]struct{} {
	value = strings.ToLower(value)
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' && r != '-'
	})
	out := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if len([]rune(field)) < 2 {
			continue
		}
		out[field] = struct{}{}
	}
	return out
}

func overlapRatio(query, candidate map[string]struct{}) float64 {
	if len(query) == 0 || len(candidate) == 0 {
		return 0
	}
	matches := 0
	for token := range candidate {
		if _, ok := query[token]; ok {
			matches++
		}
	}
	return float64(matches) / math.Sqrt(float64(len(query)*len(candidate)))
}

func inferredToolRisk(value string) float64 {
	score := 0.05
	for _, keyword := range []string{"exploit", "execute", "shell", "payload", "metasploit", "c2", "write", "delete"} {
		if strings.Contains(value, keyword) {
			score += 0.12
		}
	}
	return clamp01(score)
}

func posteriorMean(alpha, beta float64) float64 {
	if alpha <= 0 {
		alpha = 1
	}
	if beta <= 0 {
		beta = 1
	}
	return alpha / (alpha + beta)
}

func intentRisk(intent Intent) float64 {
	switch intent.Phase {
	case "exploit":
		return 0.65
	case "post_exploit":
		return 0.75
	case "credential":
		return 0.45
	case "validation":
		return 0.30
	default:
		return 0.10
	}
}

func intentCost(intent Intent) float64 {
	switch intent.Phase {
	case "exploit", "post_exploit":
		return 0.70
	case "validation", "credential":
		return 0.45
	default:
		return 0.25
	}
}

func stringValue(value interface{}) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func stringSliceValue(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := strings.TrimSpace(stringValue(item)); text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}
