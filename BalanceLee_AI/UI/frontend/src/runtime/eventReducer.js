export const initialRuntimeState = {
  lastSeq: 0,
  seenEventIds: {},
  agents: {},
  tasks: {},
  tools: {},
  findings: {},
  ideas: {},
  memories: {},
  timeline: [],
  errors: []
}

const keepRecentIds = (ids, limit = 2000) => {
  const entries = Object.entries(ids)
  if (entries.length <= limit) return ids
  return Object.fromEntries(entries.slice(entries.length - limit))
}

export function runtimeEventReducer(state, event) {
  if (!event?.event_id || !event?.type) return state
  if (state.seenEventIds[event.event_id]) return state

  const next = {
    ...state,
    lastSeq: Math.max(state.lastSeq, Number(event.seq || 0)),
    seenEventIds: keepRecentIds({ ...state.seenEventIds, [event.event_id]: true }),
    timeline: [...state.timeline, event].slice(-1000)
  }
  const payload = event.payload || {}

  switch (event.type) {
    case 'agent.status':
      next.agents = { ...state.agents, [event.source?.id || payload.agent_id]: payload }
      break
    case 'task.created':
    case 'task.status':
      if (payload.task_id) next.tasks = { ...state.tasks, [payload.task_id]: payload }
      break
    case 'tool.started':
    case 'tool.progress':
    case 'tool.completed':
      if (payload.call_id) next.tools = { ...state.tools, [payload.call_id]: payload }
      break
    case 'finding.upsert':
      if (payload.finding_id) next.findings = { ...state.findings, [payload.finding_id]: payload }
      break
    case 'idea.upsert':
      if (payload.id) next.ideas = { ...state.ideas, [payload.id]: payload }
      break
    case 'memory.upsert':
      if (payload.id) next.memories = { ...state.memories, [payload.id]: payload }
      break
    case 'runtime.error':
      next.errors = [...state.errors, event].slice(-100)
      break
    default:
      break
  }
  return next
}

export function applyRuntimeEvents(state, events = []) {
  return [...events]
    .sort((a, b) => Number(a.seq || 0) - Number(b.seq || 0))
    .reduce(runtimeEventReducer, state)
}
