# BeliefPath

BeliefPath is the optional evidence-driven online planner for BalanceLee AI.
It is disabled by default and does not replace the existing Eino, MCP, HITL,
ToolGuard, or attack-chain implementations.

## Modes

- `off`: exact legacy execution path; no planner state or behavior changes.
- `shadow`: compute and persist decisions without changing prompts or tools.
- `advisory`: inject the selected intent and recommended tools, but do not
  block other tools.
- `enforce`: inject the selected intent, expose a Top-K tool slate, and reject
  tool calls outside the current planner decision.

## Variants

- `graph_only`: evidence graph without pruning, router learning, or PUCT.
- `pruning`: graph plus failure-aware branch suspension and reopening.
- `router`: pruning plus contextual LinUCB tool ranking.
- `puct`: pruning plus bounded PUCT intent selection.
- `full`: all components.

Configure the planner in `config.yaml`:

```yaml
beliefpath:
  enabled: false
  mode: off
  variant: full
```

Changing `enabled` or `mode` through `PUT /api/config` takes effect for new
agent runs (and for later decisions in a run that already mounted the planner).
Use `off` as the behavioral baseline and `shadow` to collect counterfactual
planner decisions without influencing the agent.

Authenticated inspection endpoints:

- `GET /api/beliefpath/status`
- `GET /api/beliefpath/:conversationId/snapshot`
- `GET /api/beliefpath/:conversationId/summary?messageId=<assistant-message-id>`
- `DELETE /api/beliefpath/:conversationId`
- `DELETE /api/beliefpath/learning`

When the planner is active, finalization persists a `beliefpath_summary`
process-detail event. The summary is generated from planner tables,
`process_details`, tool executions, and model token usage rather than from LLM
text, so it can be rendered live and restored after a page refresh.

The planner treats deterministic parser output and verified terminal evidence
as facts. LLM text and ambiguous tool output remain hypotheses. Policy denial,
infrastructure failure, and malformed arguments do not reduce the strategic
success posterior.
