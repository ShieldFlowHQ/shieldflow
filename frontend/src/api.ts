import { mockDashboardData } from './mockData'
import type { 
  DashboardData, 
  DecisionEntry, 
  MetricsSnapshot,
  ShieldFlowConfig,
  PolicyConfig,
  PolicyRule,
  RealtimeMetrics,
  Decision,
  TrustLevel
} from './types'

// Re-export types
export type { 
  DashboardData, 
  DecisionEntry, 
  MetricsSnapshot,
  ShieldFlowConfig,
  PolicyConfig,
  PolicyRule,
  RealtimeMetrics,
  Decision,
  TrustLevel
}

const toJson = async <T>(path: string): Promise<T> => {
  const response = await fetch(path)
  if (!response.ok) {
    throw new Error(`Failed ${path}: ${response.status}`)
  }
  return (await response.json()) as T
}

export const loadDashboardData = async (): Promise<DashboardData> => {
  try {
    const [decisions, queue, metrics] = await Promise.all([
      toJson<DecisionEntry[]>('/dashboard/api/decisions?n=20'),
      toJson<DecisionEntry[]>('/dashboard/api/queue'),
      toJson<MetricsSnapshot>('/metrics/json'),
    ])

    return {
      decisions,
      queue,
      metrics,
      blockedActions: decisions.filter((item) => item.decision === 'BLOCK'),
      source: 'live-api',
      todo: null,
    }
  } catch {
    return mockDashboardData
  }
}

// ShieldFlow Configuration API
const defaultPolicyRules: PolicyRule[] = [
  {
    id: 'rule-1',
    name: 'Block Shell Executions',
    description: 'Block direct shell command execution unless from OWNER',
    toolPattern: 'exec',
    requiredTrustLevel: 'OWNER',
    action: 'BLOCK',
    enabled: true,
    priority: 100,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule-2',
    name: 'Require Confirmation for Email',
    description: 'Require operator confirmation for sending emails',
    toolPattern: 'email.send',
    requiredTrustLevel: 'USER',
    action: 'CONFIRM',
    enabled: true,
    priority: 90,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule-3',
    name: 'Allow Safe File Operations',
    description: 'Allow file read/write operations within workspace for trusted sources',
    toolPattern: 'file.*',
    requiredTrustLevel: 'USER',
    action: 'ALLOW',
    enabled: true,
    priority: 80,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule-4',
    name: 'Block Prompt Injection',
    description: 'Block attempts to override system instructions',
    toolPattern: '*',
    requiredTrustLevel: 'NONE',
    action: 'BLOCK',
    enabled: true,
    priority: 1000,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule-5',
    name: 'Confirm External Messages',
    description: 'Require confirmation for sending messages to external recipients',
    toolPattern: 'message.send',
    requiredTrustLevel: 'USER',
    action: 'CONFIRM',
    enabled: true,
    priority: 85,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
]

export const defaultConfig: ShieldFlowConfig = {
  enabled: true,
  upstreamLLM: {
    provider: 'openai',
    model: 'gpt-4o-mini',
    apiKey: '',
  },
  policies: {
    rules: defaultPolicyRules,
    defaultAction: 'CONFIRM',
    mode: 'moderate',
  },
  notifications: {
    email: false,
    webhook: false,
    webhookUrl: '',
  },
  logging: {
    level: 'info',
    retention: 30,
  },
}

// Simulated API delay
const simulateDelay = (ms: number = 300) => new Promise(resolve => setTimeout(resolve, ms))

// LocalStorage keys
const CONFIG_KEY = 'shieldflow_config'
const ONBOARDING_KEY = 'shieldflow_onboarding'

// Load config from localStorage or return default
export const loadConfig = async (): Promise<ShieldFlowConfig> => {
  await simulateDelay()
  try {
    const stored = localStorage.getItem(CONFIG_KEY)
    if (stored) {
      return JSON.parse(stored)
    }
  } catch (e) {
    console.error('Failed to load config:', e)
  }
  return { ...defaultConfig }
}

// Save config to localStorage
export const saveConfig = async (config: ShieldFlowConfig): Promise<void> => {
  await simulateDelay(200)
  localStorage.setItem(CONFIG_KEY, JSON.stringify(config))
}

// Load policies
export const loadPolicies = async (): Promise<PolicyConfig> => {
  const config = await loadConfig()
  return config.policies
}

// Save policies
export const savePolicies = async (policies: PolicyConfig): Promise<void> => {
  const config = await loadConfig()
  config.policies = policies
  await saveConfig(config)
}

// Toggle ShieldFlow enabled/disabled
export const toggleShieldFlow = async (enabled: boolean): Promise<void> => {
  const config = await loadConfig()
  config.enabled = enabled
  await saveConfig(config)
}

// Update upstream LLM settings
export const updateUpstreamLLM = async (llm: ShieldFlowConfig['upstreamLLM']): Promise<void> => {
  const config = await loadConfig()
  config.upstreamLLM = llm
  await saveConfig(config)
}

// Add/Update/Delete policy rule
export const savePolicyRule = async (rule: PolicyRule): Promise<void> => {
  const config = await loadConfig()
  const idx = config.policies.rules.findIndex(r => r.id === rule.id)
  if (idx >= 0) {
    config.policies.rules[idx] = { ...rule, updatedAt: new Date().toISOString() }
  } else {
    config.policies.rules.push({ ...rule, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() })
  }
  await saveConfig(config)
}

export const deletePolicyRule = async (ruleId: string): Promise<void> => {
  const config = await loadConfig()
  config.policies.rules = config.policies.rules.filter(r => r.id !== ruleId)
  await saveConfig(config)
}

// Onboarding
export interface OnboardingState {
  isComplete: boolean
  currentStep: number
}

const onboardingSteps = [
  { id: 'welcome', title: 'Welcome to ShieldFlow', description: 'Learn how ShieldFlow protects your AI workflows', skippable: false },
  { id: 'enable', title: 'Enable Protection', description: 'Turn on ShieldFlow to start protecting your system', skippable: false },
  { id: 'llm', title: 'Configure Upstream LLM', description: 'Set up the LLM that ShieldFlow uses for decision-making', skippable: true },
  { id: 'policies', title: 'Review Default Policies', description: 'Customize the security policies that control tool access', skippable: true },
  { id: 'complete', title: 'You\'re Ready!', description: 'Start using ShieldFlow to secure your AI workflows', skippable: false },
]

export const loadOnboardingState = async (): Promise<OnboardingState> => {
  await simulateDelay(100)
  try {
    const stored = localStorage.getItem(ONBOARDING_KEY)
    if (stored) {
      return JSON.parse(stored)
    }
  } catch (e) {
    console.error('Failed to load onboarding state:', e)
  }
  return { isComplete: false, currentStep: 0 }
}

export const saveOnboardingState = async (state: OnboardingState): Promise<void> => {
  localStorage.setItem(ONBOARDING_KEY, JSON.stringify(state))
}

export const resetOnboarding = async (): Promise<void> => {
  localStorage.removeItem(ONBOARDING_KEY)
}

// Generate mock real-time metrics
export const loadRealtimeMetrics = async (): Promise<RealtimeMetrics> => {
  await simulateDelay(150)
  return {
    requestsPerMinute: Math.floor(Math.random() * 30) + 5,
    decisionsPerMinute: {
      allow: Math.floor(Math.random() * 20) + 10,
      block: Math.floor(Math.random() * 5),
      confirm: Math.floor(Math.random() * 3),
    },
    activeSessions: Math.floor(Math.random() * 8) + 1,
    queueDepth: Math.floor(Math.random() * 5),
    uptime: Math.floor(Math.random() * 86400) + 3600, // seconds
  }
}

export { onboardingSteps }
