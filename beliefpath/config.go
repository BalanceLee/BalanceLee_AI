package beliefpath

import (
	"strings"
	"time"
)

const (
	ModeOff      = "off"
	ModeShadow   = "shadow"
	ModeAdvisory = "advisory"
	ModeEnforce  = "enforce"

	VariantGraphOnly = "graph_only"
	VariantPruning   = "pruning"
	VariantRouter    = "router"
	VariantPUCT      = "puct"
	VariantFull      = "full"
)

// Config controls the planner independently from the existing Eino modes.
// Enabled is a master kill switch. Mode controls whether decisions are only
// observed, suggested to the model, or enforced at the tool boundary.
type Config struct {
	Enabled               bool    `yaml:"enabled" json:"enabled"`
	Mode                  string  `yaml:"mode,omitempty" json:"mode,omitempty"`
	Variant               string  `yaml:"variant,omitempty" json:"variant,omitempty"`
	DecisionTimeoutMS     int     `yaml:"decision_timeout_ms,omitempty" json:"decision_timeout_ms,omitempty"`
	TopKTools             int     `yaml:"top_k_tools,omitempty" json:"top_k_tools,omitempty"`
	MaxIntents            int     `yaml:"max_intents,omitempty" json:"max_intents,omitempty"`
	RandomSeed            int64   `yaml:"random_seed,omitempty" json:"random_seed,omitempty"`
	Exploration           float64 `yaml:"exploration,omitempty" json:"exploration,omitempty"`
	InformationGainWeight float64 `yaml:"information_gain_weight,omitempty" json:"information_gain_weight,omitempty"`
	CostWeight            float64 `yaml:"cost_weight,omitempty" json:"cost_weight,omitempty"`
	RiskWeight            float64 `yaml:"risk_weight,omitempty" json:"risk_weight,omitempty"`
	RepeatWeight          float64 `yaml:"repeat_weight,omitempty" json:"repeat_weight,omitempty"`
	MinEvidenceAttempts   int     `yaml:"min_evidence_attempts,omitempty" json:"min_evidence_attempts,omitempty"`
	SoftPruneMargin       float64 `yaml:"soft_prune_margin,omitempty" json:"soft_prune_margin,omitempty"`
	RepeatLimit           int     `yaml:"repeat_limit,omitempty" json:"repeat_limit,omitempty"`
	CooldownRevisions     int64   `yaml:"cooldown_revisions,omitempty" json:"cooldown_revisions,omitempty"`
	PUCTSimulations       int     `yaml:"puct_simulations,omitempty" json:"puct_simulations,omitempty"`
	ExplorationFloor      float64 `yaml:"exploration_floor,omitempty" json:"exploration_floor,omitempty"`
}

func (c Config) Effective() Config {
	out := c
	if !out.Enabled {
		out.Mode = ModeOff
	}
	switch strings.ToLower(strings.TrimSpace(out.Mode)) {
	case ModeShadow, ModeAdvisory, ModeEnforce:
		out.Mode = strings.ToLower(strings.TrimSpace(out.Mode))
	default:
		out.Mode = ModeOff
	}
	switch strings.ToLower(strings.TrimSpace(out.Variant)) {
	case VariantGraphOnly, VariantPruning, VariantRouter, VariantPUCT, VariantFull:
		out.Variant = strings.ToLower(strings.TrimSpace(out.Variant))
	default:
		out.Variant = VariantFull
	}
	if out.DecisionTimeoutMS <= 0 {
		out.DecisionTimeoutMS = 150
	}
	if out.TopKTools <= 0 {
		out.TopKTools = 5
	}
	if out.TopKTools > 12 {
		out.TopKTools = 12
	}
	if out.MaxIntents <= 0 {
		out.MaxIntents = 6
	}
	if out.MaxIntents > 12 {
		out.MaxIntents = 12
	}
	if out.RandomSeed == 0 {
		out.RandomSeed = 42
	}
	if out.Exploration <= 0 {
		out.Exploration = 1.25
	}
	if out.InformationGainWeight <= 0 {
		out.InformationGainWeight = 0.35
	}
	if out.CostWeight <= 0 {
		out.CostWeight = 0.20
	}
	if out.RiskWeight <= 0 {
		out.RiskWeight = 0.35
	}
	if out.RepeatWeight <= 0 {
		out.RepeatWeight = 0.45
	}
	if out.MinEvidenceAttempts <= 0 {
		out.MinEvidenceAttempts = 2
	}
	if out.SoftPruneMargin <= 0 {
		out.SoftPruneMargin = 0.10
	}
	if out.RepeatLimit <= 0 {
		out.RepeatLimit = 3
	}
	if out.CooldownRevisions <= 0 {
		out.CooldownRevisions = 3
	}
	if out.PUCTSimulations <= 0 {
		out.PUCTSimulations = 48
	}
	if out.PUCTSimulations > 256 {
		out.PUCTSimulations = 256
	}
	if out.ExplorationFloor <= 0 {
		out.ExplorationFloor = 0.05
	}
	if out.ExplorationFloor > 0.25 {
		out.ExplorationFloor = 0.25
	}
	return out
}

func (c Config) Active() bool {
	effective := c.Effective()
	return effective.Enabled && effective.Mode != ModeOff
}

func (c Config) Enforces() bool {
	effective := c.Effective()
	return effective.Active() &&
		effective.Variant != VariantGraphOnly &&
		effective.Mode == ModeEnforce
}

func (c Config) Advises() bool {
	effective := c.Effective()
	return effective.Active() &&
		effective.Variant != VariantGraphOnly &&
		(effective.Mode == ModeAdvisory || effective.Mode == ModeEnforce)
}

func (c Config) UsesPruning() bool {
	switch c.Effective().Variant {
	case VariantPruning, VariantRouter, VariantPUCT, VariantFull:
		return true
	default:
		return false
	}
}

func (c Config) UsesRouter() bool {
	switch c.Effective().Variant {
	case VariantRouter, VariantFull:
		return true
	default:
		return false
	}
}

func (c Config) UsesPUCT() bool {
	switch c.Effective().Variant {
	case VariantPUCT, VariantFull:
		return true
	default:
		return false
	}
}

func (c Config) DecisionTimeout() time.Duration {
	return time.Duration(c.Effective().DecisionTimeoutMS) * time.Millisecond
}
