export type Decision = 'ALLOW' | 'BLOCK' | 'CONFIRM'

export interface DecisionEntry {
  entry_id: string
  timestamp: string
  request_id: string
  tool_name: string
  decision: Decision
  reason: string
  trigger_source: string | null
  trigger_trust: string
  matched_patterns: string[]
  normalisation_flags: string[]
  data_classification: string | null
}

export interface MetricsSnapshot {
  requests_total: number
  decisions: {
    block_total: number
    allow_total: number
    confirm_total: number
  }
  decisions_by_tool: Record<string, Record<string, number>>
  top_blocked_patterns: Array<[string, number]>
  top_normalisation_flags: Array<[string, number]>
  anomaly?: {
    active_sessions: number
    total_spikes: number
    sessions_at_risk: number
  }
}

export interface DashboardData {
  decisions: DecisionEntry[]
  blockedActions: DecisionEntry[]
  queue: DecisionEntry[]
  metrics: MetricsSnapshot
  source: 'live-api' | 'mock-fallback'
  todo: string | null
}
