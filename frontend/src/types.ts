export type Decision = 'ALLOW' | 'BLOCK' | 'CONFIRM'

export type TrustLevel = 'OWNER' | 'USER' | 'SYSTEM' | 'AGENT' | 'TOOL' | 'NONE'

export interface DecisionEntry {
  entry_id: string
  timestamp: string
  request_id: string
  tool_name: string
  decision: Decision
  reason: string
  trigger_source: string | null
  trigger_trust: TrustLevel
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
  source: 'live-api' | 'demo-mock' | 'mock-fallback'
  todo: string | null
}

// Policy Configuration Types
export interface PolicyRule {
  id: string
  name: string
  description: string
  toolPattern: string
  requiredTrustLevel: TrustLevel
  action: Decision
  enabled: boolean
  priority: number
  createdAt: string
  updatedAt: string
}

export interface PolicyConfig {
  rules: PolicyRule[]
  defaultAction: Decision
  mode: 'strict' | 'moderate' | 'permissive'
}

// ShieldFlow Settings
export interface ShieldFlowConfig {
  enabled: boolean
  upstreamLLM: {
    provider: 'openai' | 'anthropic' | 'google' | 'local' | 'custom'
    model: string
    apiKey?: string
    endpoint?: string
  }
  policies: PolicyConfig
  notifications: {
    email: boolean
    webhook: boolean
    webhookUrl?: string
  }
  logging: {
    level: 'debug' | 'info' | 'warning' | 'error'
    retention: number // days
  }
}

// Real-time metrics
export interface RealtimeMetrics {
  requestsPerMinute: number
  decisionsPerMinute: {
    allow: number
    block: number
    confirm: number
  }
  activeSessions: number
  queueDepth: number
  uptime: number
}

// Onboarding
export interface OnboardingStep {
  id: string
  title: string
  description: string
  completed: boolean
  skippable: boolean
}

export interface OnboardingState {
  isComplete: boolean
  currentStep: number
  steps: OnboardingStep[]
}
