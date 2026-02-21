import React, { useState, useEffect, useMemo, useRef } from 'react'
import './index.css'
import { 
  loadDashboardData, 
  loadConfig, 
  toggleShieldFlow,
  updateUpstreamLLM,
  savePolicyRule,
  deletePolicyRule,
  loadOnboardingState,
  saveOnboardingState,
  resetOnboarding,
  onboardingSteps,
  type ShieldFlowConfig,
  type PolicyRule,
  type Decision,
  type TrustLevel,
  type DecisionEntry,
  type RealtimeMetrics
} from './api'

// ========== Error Boundary Component ==========
interface ErrorBoundaryProps {
  children: React.ReactNode
}

interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Error Boundary caught an error:', error, errorInfo)
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--bg-primary)' }}>
          <div className="card max-w-md text-center">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-red-500/15 flex items-center justify-center">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
            </div>
            <h1 className="text-xl font-semibold text-white mb-2">Something went wrong</h1>
            <p className="text-zinc-400 text-sm mb-6">
              {this.state.error?.message || 'An unexpected error occurred'}
            </p>
            <button onClick={this.handleRetry} className="btn btn-primary">
              Try Again
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

// ========== Theme Hook ==========
function useTheme() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const stored = localStorage.getItem('shieldflow_theme')
    return (stored as 'dark' | 'light') || 'dark'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('shieldflow_theme', theme)
  }, [theme])

  const toggleTheme = () => setTheme(t => t === 'dark' ? 'light' : 'dark')

  return { theme, toggleTheme }
}

// ========== Dashboard Filters Hook (URL Persistence) ==========
function useDashboardFilters() {
  const [searchQuery, setSearchQuery] = useState(() => {
    const params = new URLSearchParams(window.location.search)
    return params.get('search') || ''
  })
  const [decisionFilter, setDecisionFilter] = useState<Decision | ''>(() => {
    const params = new URLSearchParams(window.location.search)
    return (params.get('decision') as Decision) || ''
  })
  const [trustFilter, setTrustFilter] = useState<TrustLevel | ''>(() => {
    const params = new URLSearchParams(window.location.search)
    return (params.get('trust') as TrustLevel) || ''
  })

  // Update URL when filters change
  useEffect(() => {
    const params = new URLSearchParams()
    if (searchQuery) params.set('search', searchQuery)
    if (decisionFilter) params.set('decision', decisionFilter)
    if (trustFilter) params.set('trust', trustFilter)
    
    const newUrl = params.toString() 
      ? `${window.location.pathname}?${params.toString()}`
      : window.location.pathname
    window.history.replaceState({}, '', newUrl)
  }, [searchQuery, decisionFilter, trustFilter])

  return { searchQuery, setSearchQuery, decisionFilter, setDecisionFilter, trustFilter, setTrustFilter }
}

// Icons
const Icons = {
  Shield: () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Dashboard: () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="3" y="14" width="7" height="7" rx="1"/>
      <rect x="14" y="14" width="7" height="7" rx="1"/>
    </svg>
  ),
  Settings: () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="3"/>
      <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
    </svg>
  ),
  Policies: () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14,2 14,8 20,8"/>
      <line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/>
    </svg>
  ),
  Activity: () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="22,12 18,12 15,21 9,3 6,12 2,12"/>
    </svg>
  ),
  Check: () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="20,6 9,17 4,12"/>
    </svg>
  ),
  Plus: () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <line x1="12" y1="5" x2="12" y2="19"/>
      <line x1="5" y1="12" x2="19" y2="12"/>
    </svg>
  ),
  Trash: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="3,6 5,6 21,6"/>
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
    </svg>
  ),
  ChevronRight: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="9,18 15,12 9,6"/>
    </svg>
  ),
  Lock: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  ),
  AlertTriangle: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  ),
  Clock: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10"/>
      <polyline points="12,6 12,12 16,14"/>
    </svg>
  ),
  Spinner: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="animate-spin">
      <circle cx="12" cy="12" r="10" strokeOpacity="0.25"/>
      <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round"/>
    </svg>
  ),
  X: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <line x1="18" y1="6" x2="6" y2="18"/>
      <line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  ),
  Refresh: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
      <path d="M3 3v5h5"/>
      <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/>
      <path d="M16 21h5v-5"/>
    </svg>
  ),
  Keyboard: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="2" y="4" width="20" height="16" rx="2" ry="2"/>
      <line x1="6" y1="8" x2="6" y2="8"/>
      <line x1="10" y1="8" x2="10" y2="8"/>
      <line x1="14" y1="8" x2="14" y2="8"/>
      <line x1="18" y1="8" x2="18" y2="8"/>
      <line x1="6" y1="12" x2="6" y2="12"/>
      <line x1="10" y1="12" x2="10" y2="12"/>
      <line x1="14" y1="12" x2="14" y2="12"/>
      <line x1="18" y1="12" x2="18" y2="12"/>
      <line x1="7" y1="16" x2="17" y2="16"/>
    </svg>
  ),
  Download: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
      <polyline points="7,10 12,15 17,10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  ),
  Upload: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
      <polyline points="17,8 12,3 7,8"/>
      <line x1="12" y1="3" x2="12" y2="15"/>
    </svg>
  ),
}

// Toast notification component
type ToastType = 'success' | 'error'
interface Toast {
  id: number
  message: string
  type: ToastType
}

function ToastContainer({ toasts, onRemove }: { toasts: Toast[]; onRemove: (id: number) => void }) {
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg animate-slideUp ${
            toast.type === 'success' 
              ? 'bg-emerald-500/15 border border-emerald-500/20 text-emerald-400' 
              : 'bg-red-500/15 border border-red-500/20 text-red-400'
          }`}
        >
          {toast.type === 'success' ? <Icons.Check /> : <Icons.AlertTriangle />}
          <span className="text-sm">{toast.message}</span>
          <button onClick={() => onRemove(toast.id)} className="ml-2 hover:opacity-70">
            <Icons.X />
          </button>
        </div>
      ))}
    </div>
  )
}

const trustColors: Record<TrustLevel, string> = {
  OWNER: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20',
  USER: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
  SYSTEM: 'text-purple-400 bg-purple-400/10 border-purple-400/20',
  AGENT: 'text-amber-400 bg-amber-400/10 border-amber-400/20',
  TOOL: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/20',
  NONE: 'text-red-400 bg-red-400/10 border-red-400/20',
}

const decisionColors: Record<Decision, { bg: string; text: string; border: string }> = {
  ALLOW: { bg: 'bg-emerald-500/15', text: 'text-emerald-400', border: 'border-emerald-500/20' },
  BLOCK: { bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/20' },
  CONFIRM: { bg: 'bg-amber-500/15', text: 'text-amber-400', border: 'border-amber-500/20' },
}

const formatUptime = (seconds: number): string => {
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

// Onboarding Modal
function OnboardingModal({ onComplete }: { onComplete: () => void }) {
  const [currentStep, setCurrentStep] = useState(0)
  const [config, setConfig] = useState<ShieldFlowConfig | null>(null)
  const [llmSettings, setLlmSettings] = useState({ provider: 'openai', model: 'gpt-4o-mini', apiKey: '' })
  const [isLoading, setIsLoading] = useState(true)
  const modalRef = useRef<HTMLDivElement>(null)

  // Focus trapping
  useEffect(() => {
    // Focus the modal when it opens
    const modal = modalRef.current
    if (!modal) return

    // Get all focusable elements within the modal
    const getFocusableElements = () => {
      const focusableSelectors = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      return Array.from(modal.querySelectorAll<HTMLElement>(focusableSelectors))
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onComplete()
        return
      }

      if (e.key === 'Tab') {
        const focusableElements = getFocusableElements()
        if (focusableElements.length === 0) return

        const firstElement = focusableElements[0]
        const lastElement = focusableElements[focusableElements.length - 1]

        if (e.shiftKey) {
          // Shift + Tab: wrap from first to last
          if (document.activeElement === firstElement) {
            e.preventDefault()
            lastElement.focus()
          }
        } else {
          // Tab: wrap from last to first
          if (document.activeElement === lastElement) {
            e.preventDefault()
            firstElement.focus()
          }
        }
      }
    }

    // Focus first element when modal opens
    setTimeout(() => {
      const focusableElements = getFocusableElements()
      if (focusableElements.length > 0) {
        focusableElements[0].focus()
      }
    }, 100)

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [onComplete])

  useEffect(() => {
    loadConfig().then(c => {
      setConfig(c)
      setLlmSettings(c.upstreamLLM as { provider: string; model: string; apiKey: string })
      setIsLoading(false)
    })
  }, [])

  const handleNext = async () => {
    if (currentStep < onboardingSteps.length - 1) {
      setCurrentStep(currentStep + 1)
    } else {
      await saveOnboardingState({ isComplete: true, currentStep: 0 })
      onComplete()
    }
  }

  const handleSkip = async () => {
    await saveOnboardingState({ isComplete: true, currentStep: 0 })
    onComplete()
  }

  const handleEnableShieldFlow = async () => {
    if (config) {
      await toggleShieldFlow(true)
      setConfig({ ...config, enabled: true })
    }
  }

  const handleSaveLLM = async () => {
    if (config) {
      await updateUpstreamLLM(llmSettings as ShieldFlowConfig['upstreamLLM'])
      setConfig({ ...config, upstreamLLM: llmSettings as ShieldFlowConfig['upstreamLLM'] })
    }
  }

  if (isLoading) {
    return (
      <div className="modal-overlay">
        <div className="modal flex items-center justify-center min-h-[200px]">
          <div className="animate-pulse text-zinc-400">Loading...</div>
        </div>
      </div>
    )
  }

  const step = onboardingSteps[currentStep]

  return (
    <div className="modal-overlay">
      <div className="modal max-w-lg" ref={modalRef}>
        <div className="flex gap-1 mb-6">
          {onboardingSteps.map((s, i) => (
            <div key={s.id} className={`h-1 flex-1 rounded-full transition-all ${i <= currentStep ? 'bg-cyan-500' : 'bg-zinc-700'}`} />
          ))}
        </div>
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/15 flex items-center justify-center">
              {currentStep === 0 && <Icons.Shield />}
              {currentStep === 1 && <Icons.Lock />}
              {currentStep === 2 && <Icons.Check />}
              {currentStep === 3 && <Icons.Check />}
            </div>
            <div>
              <h2 className="text-xl font-semibold text-white">{step.title}</h2>
              <p className="text-sm text-zinc-400">{step.description}</p>
            </div>
          </div>
          {currentStep === 0 && (
            <div className="bg-zinc-800/50 rounded-xl p-4 space-y-3">
              <p className="text-zinc-300">ShieldFlow is a security layer for AI agents that evaluates every tool execution against configurable policies.</p>
              <ul className="space-y-2 text-sm text-zinc-400">
                <li className="flex items-center gap-2"><Icons.Check /> Blocks dangerous operations automatically</li>
                <li className="flex items-center gap-2"><Icons.Check /> Requires confirmation for sensitive actions</li>
                <li className="flex items-center gap-2"><Icons.Check /> Provides detailed audit logs</li>
              </ul>
            </div>
          )}
          {currentStep === 1 && (
            <div className="bg-zinc-800/50 rounded-xl p-4">
              <p className="text-zinc-300 mb-4">Enable ShieldFlow to start protecting your AI workflows.</p>
              <button onClick={handleEnableShieldFlow} className="btn btn-primary w-full">
                <Icons.Lock /> Enable ShieldFlow Protection
              </button>
              {config?.enabled && <p className="text-emerald-400 text-sm mt-3 flex items-center gap-2"><Icons.Check /> ShieldFlow is now active!</p>}
            </div>
          )}
          {currentStep === 2 && (
            <div className="bg-zinc-800/50 rounded-xl p-4 space-y-4">
              <p className="text-zinc-300">Configure the upstream LLM that ShieldFlow uses for decision-making.</p>
              <div>
                <label className="block text-sm text-zinc-400 mb-1">Provider</label>
                <select value={llmSettings.provider} onChange={(e) => setLlmSettings({ ...llmSettings, provider: e.target.value })} className="input">
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="google">Google</option>
                  <option value="local">Local / Custom</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-zinc-400 mb-1">Model</label>
                <input type="text" value={llmSettings.model} onChange={(e) => setLlmSettings({ ...llmSettings, model: e.target.value })} className="input" placeholder="gpt-4o-mini" />
              </div>
              <div>
                <label className="block text-sm text-zinc-400 mb-1">API Key</label>
                <input type="password" value={llmSettings.apiKey} onChange={(e) => setLlmSettings({ ...llmSettings, apiKey: e.target.value })} className="input" placeholder="sk-..." />
                <p className="text-xs text-amber-400 mt-1">🔒 Stored in memory only during session for security</p>
              </div>
              <button onClick={handleSaveLLM} className="btn btn-secondary w-full">Save LLM Configuration</button>
            </div>
          )}
          {currentStep === 3 && (
            <div className="bg-zinc-800/50 rounded-xl p-4 space-y-3">
              <p className="text-zinc-300 mb-3">Default policies are pre-configured. You can customize them later in Settings.</p>
              {config?.policies.rules.slice(0, 3).map((rule) => (
                <div key={rule.id} className="flex items-center justify-between p-3 bg-zinc-900/50 rounded-lg">
                  <div>
                    <div className="text-sm text-white">{rule.name}</div>
                    <div className="text-xs text-zinc-500">{rule.toolPattern} → {rule.action}</div>
                  </div>
                  <span className={`badge ${decisionColors[rule.action].bg} ${decisionColors[rule.action].text} ${decisionColors[rule.action].border}`}>{rule.action}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="flex items-center justify-between">
          <button onClick={handleSkip} className="btn btn-ghost text-zinc-500">Skip</button>
          <button onClick={handleNext} className="btn btn-primary">{currentStep === onboardingSteps.length - 1 ? 'Finish' : 'Continue'}<Icons.ChevronRight /></button>
        </div>
      </div>
    </div>
  )
}

// Policy Rule Modal
function PolicyRuleModal({ rule, onSave, onClose }: { rule?: PolicyRule; onSave: (rule: PolicyRule) => void; onClose: () => void }) {
  const [formData, setFormData] = useState<PolicyRule>(
    rule || {
      id: `rule-${Date.now()}`,
      name: '',
      description: '',
      toolPattern: '*',
      requiredTrustLevel: 'USER',
      action: 'ALLOW',
      enabled: true,
      priority: 50,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }
  )
  const modalRef = useRef<HTMLDivElement>(null)

  // Focus trapping
  useEffect(() => {
    const modal = modalRef.current
    if (!modal) return

    const getFocusableElements = () => {
      const focusableSelectors = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      return Array.from(modal.querySelectorAll<HTMLElement>(focusableSelectors))
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
        return
      }

      if (e.key === 'Tab') {
        const focusableElements = getFocusableElements()
        if (focusableElements.length === 0) return

        const firstElement = focusableElements[0]
        const lastElement = focusableElements[focusableElements.length - 1]

        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            e.preventDefault()
            lastElement.focus()
          }
        } else {
          if (document.activeElement === lastElement) {
            e.preventDefault()
            firstElement.focus()
          }
        }
      }
    }

    setTimeout(() => {
      const focusableElements = getFocusableElements()
      if (focusableElements.length > 0) {
        focusableElements[0].focus()
      }
    }, 100)

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave(formData)
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal max-w-md" ref={modalRef} onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-white mb-4">{rule ? 'Edit Policy Rule' : 'Create Policy Rule'}</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Rule Name</label>
            <input type="text" value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} className="input" placeholder="e.g., Block dangerous commands" required />
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Description</label>
            <input type="text" value={formData.description} onChange={(e) => setFormData({ ...formData, description: e.target.value })} className="input" placeholder="Describe what this rule does" />
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Tool Pattern</label>
            <input type="text" value={formData.toolPattern} onChange={(e) => setFormData({ ...formData, toolPattern: e.target.value })} className="input font-mono" placeholder="e.g., exec, file.*, email.send" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-zinc-400 mb-1">Required Trust</label>
              <select value={formData.requiredTrustLevel} onChange={(e) => setFormData({ ...formData, requiredTrustLevel: e.target.value as TrustLevel })} className="input">
                <option value="OWNER">OWNER</option>
                <option value="USER">USER</option>
                <option value="SYSTEM">SYSTEM</option>
                <option value="AGENT">AGENT</option>
                <option value="TOOL">TOOL</option>
                <option value="NONE">NONE</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-zinc-400 mb-1">Action</label>
              <select value={formData.action} onChange={(e) => setFormData({ ...formData, action: e.target.value as Decision })} className="input">
                <option value="ALLOW">ALLOW</option>
                <option value="BLOCK">BLOCK</option>
                <option value="CONFIRM">CONFIRM</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Priority</label>
            <input type="number" value={formData.priority} onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 50 })} className="input" min="1" max="1000" />
          </div>
          <div className="flex items-center justify-between pt-2">
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={formData.enabled} onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })} className="w-4 h-4 rounded bg-zinc-800 border-zinc-600" />
              <span className="text-sm text-zinc-300">Enabled</span>
            </label>
          </div>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn btn-secondary flex-1">Cancel</button>
            <button type="submit" className="btn btn-primary flex-1">{rule ? 'Save Changes' : 'Create Rule'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// Dashboard View
function DashboardView({ data, realtimeMetrics, onRefresh, isRefreshing, lastUpdated, filters }: { 
  data: any; 
  realtimeMetrics: RealtimeMetrics; 
  onRefresh?: () => Promise<void>; 
  isRefreshing?: boolean; 
  lastUpdated?: Date | null;
  filters: {
    searchQuery: string
    setSearchQuery: (v: string) => void
    decisionFilter: Decision | ''
    setDecisionFilter: (v: Decision | '') => void
    trustFilter: TrustLevel | ''
    setTrustFilter: (v: TrustLevel | '') => void
  }
}) {
  const percent = (val: number, total: number) => total > 0 ? Math.round((val / total) * 100) : 0
  const { searchQuery, setSearchQuery, decisionFilter, setDecisionFilter, trustFilter, setTrustFilter } = filters

  const filteredDecisions = useMemo(() => {
    return data.decisions.filter((entry: DecisionEntry) => {
      const matchesSearch = !searchQuery || 
        entry.tool_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        entry.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
        entry.request_id.toLowerCase().includes(searchQuery.toLowerCase())
      const matchesDecision = !decisionFilter || entry.decision === decisionFilter
      const matchesTrust = !trustFilter || entry.trigger_trust === trustFilter
      return matchesSearch && matchesDecision && matchesTrust
    })
  }, [data.decisions, searchQuery, decisionFilter, trustFilter])

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Dashboard</h1>
          <p className="text-zinc-400 text-sm">Real-time ShieldFlow activity monitoring</p>
        </div>
        <div className="flex items-center gap-4">
          {lastUpdated && (
            <span className="text-xs text-zinc-500">
              Last updated: {lastUpdated.toLocaleTimeString()}
            </span>
          )}
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className={`btn btn-ghost flex items-center gap-2 ${isRefreshing ? 'opacity-70' : ''}`}
            >
              <span className={isRefreshing ? 'animate-spin' : ''}>
                <Icons.Refresh />
              </span>
              {isRefreshing ? 'Refreshing...' : 'Refresh'}
            </button>
          )}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs ${data.source === 'live-api' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/15 text-amber-400 border border-amber-500/20'}`}>
            <span className={`w-2 h-2 rounded-full ${data.source === 'live-api' ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse-slow'}`} />
            {data.source === 'live-api' ? 'Live API' : 'Demo Mode'}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/15 flex items-center justify-center"><Icons.Activity /></div>
            <div>
              <p className="text-2xl font-semibold text-white">{data.metrics.requests_total}</p>
              <p className="text-xs text-zinc-500">Total Requests</p>
            </div>
          </div>
          <div className="mt-3 text-xs text-zinc-500"><span className="text-emerald-400">{realtimeMetrics.requestsPerMinute}/min</span> current rate</div>
        </div>
        <div className="stat-card">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/15 flex items-center justify-center"><Icons.Lock /></div>
            <div>
              <p className="text-2xl font-semibold text-white">{data.metrics.decisions.block_total}</p>
              <p className="text-xs text-zinc-500">Blocked Actions</p>
            </div>
          </div>
        </div>
        <div className="stat-card">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/15 flex items-center justify-center"><Icons.AlertTriangle /></div>
            <div>
              <p className="text-2xl font-semibold text-white">{data.queue.length}</p>
              <p className="text-xs text-zinc-500">Pending Confirmations</p>
            </div>
          </div>
        </div>
        <div className="stat-card">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/15 flex items-center justify-center"><Icons.Clock /></div>
            <div>
              <p className="text-2xl font-semibold text-white">{formatUptime(realtimeMetrics.uptime)}</p>
              <p className="text-xs text-zinc-500">Uptime</p>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-medium text-white mb-4">Decision Breakdown</h2>
        <div className="grid grid-cols-3 gap-4">
          <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
            <div className="flex items-center justify-between mb-2">
              <span className="text-emerald-400 text-sm font-medium">Allowed</span>
              <span className="text-2xl font-semibold text-white">{data.metrics.decisions.allow_total}</span>
            </div>
            <div className="h-1.5 bg-zinc-700 rounded-full overflow-hidden">
              <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${percent(data.metrics.decisions.allow_total, data.metrics.requests_total)}%` }} />
            </div>
          </div>
          <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20">
            <div className="flex items-center justify-between mb-2">
              <span className="text-red-400 text-sm font-medium">Blocked</span>
              <span className="text-2xl font-semibold text-white">{data.metrics.decisions.block_total}</span>
            </div>
            <div className="h-1.5 bg-zinc-700 rounded-full overflow-hidden">
              <div className="h-full bg-red-500 rounded-full" style={{ width: `${percent(data.metrics.decisions.block_total, data.metrics.requests_total)}%` }} />
            </div>
          </div>
          <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/20">
            <div className="flex items-center justify-between mb-2">
              <span className="text-amber-400 text-sm font-medium">Confirm</span>
              <span className="text-2xl font-semibold text-white">{data.metrics.decisions.confirm_total}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-medium text-white mb-4">Recent Decisions</h2>
        <div className="flex flex-wrap gap-3 mb-4">
          <input
            type="text"
            placeholder="Search decisions..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input flex-1 min-w-[200px]"
          />
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value as Decision | '')}
            className="input w-36"
          >
            <option value="">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
            <option value="CONFIRM">CONFIRM</option>
          </select>
          <select
            value={trustFilter}
            onChange={(e) => setTrustFilter(e.target.value as TrustLevel | '')}
            className="input w-36"
          >
            <option value="">All Trust Levels</option>
            <option value="OWNER">OWNER</option>
            <option value="USER">USER</option>
            <option value="SYSTEM">SYSTEM</option>
            <option value="AGENT">AGENT</option>
            <option value="TOOL">TOOL</option>
            <option value="NONE">NONE</option>
          </select>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr><th>Time</th><th>Tool</th><th>Decision</th><th>Trust</th><th>Reason</th></tr>
            </thead>
            <tbody>
              {filteredDecisions.slice(0, 10).map((entry: DecisionEntry) => (
                <tr key={entry.entry_id}>
                  <td className="text-zinc-500 whitespace-nowrap">{new Date(entry.timestamp).toLocaleTimeString()}</td>
                  <td><code className="code">{entry.tool_name}</code></td>
                  <td><span className={`badge ${decisionColors[entry.decision].bg} ${decisionColors[entry.decision].text} ${decisionColors[entry.decision].border}`}>{entry.decision}</span></td>
                  <td><span className={`badge ${trustColors[entry.trigger_trust]}`}>{entry.trigger_trust}</span></td>
                  <td className="text-zinc-400 max-w-xs truncate">{entry.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// Settings View
function SettingsView({ config, onConfigChange, theme, onToggleTheme, onRestartOnboarding }: { 
  config: ShieldFlowConfig, 
  onConfigChange: (c: ShieldFlowConfig) => void,
  theme: 'dark' | 'light',
  onToggleTheme: () => void,
  onRestartOnboarding: () => void
}) {
  const [llmSettings, setLlmSettings] = useState(config.upstreamLLM)
  const [saving, setSaving] = useState(false)

  const handleToggleEnabled = async () => {
    setSaving(true)
    await toggleShieldFlow(!config.enabled)
    onConfigChange({ ...config, enabled: !config.enabled })
    setSaving(false)
  }

  const handleSaveLLM = async () => {
    setSaving(true)
    await updateUpstreamLLM(llmSettings)
    onConfigChange({ ...config, upstreamLLM: llmSettings })
    setSaving(false)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Settings</h1>
        <p className="text-zinc-400 text-sm">Configure ShieldFlow behavior</p>
      </div>

      {/* Theme Toggle */}
      <div className="card">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-medium text-white">Appearance</h2>
            <p className="text-sm text-zinc-400">Switch between dark and light mode</p>
          </div>
          <button 
            onClick={onToggleTheme}
            className="flex items-center gap-3 px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 transition-colors"
          >
            {theme === 'dark' ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
              </svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="5"/>
                <line x1="12" y1="1" x2="12" y2="3"/>
                <line x1="12" y1="21" x2="12" y2="23"/>
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
                <line x1="1" y1="12" x2="3" y2="12"/>
                <line x1="21" y1="12" x2="23" y2="12"/>
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
              </svg>
            )}
            <span className="text-sm text-white">{theme === 'dark' ? 'Dark' : 'Light'}</span>
          </button>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-medium text-white">ShieldFlow Protection</h2>
            <p className="text-sm text-zinc-400">Enable or disable all security filtering</p>
          </div>
          <button onClick={handleToggleEnabled} disabled={saving} className={`toggle ${config.enabled ? 'active' : ''}`} />
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-medium text-white mb-4">Upstream LLM Configuration</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Provider</label>
            <select value={llmSettings.provider} onChange={(e) => setLlmSettings({ ...llmSettings, provider: e.target.value as any })} className="input">
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="google">Google</option>
              <option value="local">Local / Custom</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Model</label>
            <input type="text" value={llmSettings.model} onChange={(e) => setLlmSettings({ ...llmSettings, model: e.target.value })} className="input" placeholder="gpt-4o-mini" />
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">API Key</label>
            <input type="password" value={llmSettings.apiKey || ''} onChange={(e) => setLlmSettings({ ...llmSettings, apiKey: e.target.value })} className="input" placeholder="sk-..." />
            <p className="text-xs text-amber-400 mt-1">🔒 Stored in memory only during session for security</p>
          </div>
          <button onClick={handleSaveLLM} disabled={saving} className="btn btn-primary">
            {saving ? 'Saving...' : 'Save LLM Configuration'}
          </button>
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-medium text-white mb-4">Logging</h2>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Log Level</label>
            <select value={config.logging.level} onChange={(e) => onConfigChange({ ...config, logging: { ...config.logging, level: e.target.value as any } })} className="input">
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="error">Error</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Retention (days)</label>
            <input type="number" value={config.logging.retention} onChange={(e) => onConfigChange({ ...config, logging: { ...config.logging, retention: parseInt(e.target.value) || 30 } })} className="input" min="1" max="365" />
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-medium text-white mb-4">Configuration</h2>
        <p className="text-sm text-zinc-400 mb-4">Export or import your ShieldFlow configuration for backup, sharing, or migration.</p>
        <div className="flex gap-3">
          <button 
            onClick={() => {
              const dataStr = JSON.stringify(config, null, 2)
              const blob = new Blob([dataStr], { type: 'application/json' })
              const url = URL.createObjectURL(blob)
              const link = document.createElement('a')
              link.href = url
              link.download = `shieldflow-config-${new Date().toISOString().split('T')[0]}.json`
              document.body.appendChild(link)
              link.click()
              document.body.removeChild(link)
              URL.revokeObjectURL(url)
            }}
            className="btn btn-secondary flex items-center gap-2"
          >
            <Icons.Download /> Export Config
          </button>
          <label className="btn btn-secondary flex items-center gap-2 cursor-pointer">
            <Icons.Upload /> Import Config
            <input 
              type="file" 
              accept=".json" 
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (!file) return
                
                const reader = new FileReader()
                reader.onload = (event) => {
                  try {
                    const importedConfig = JSON.parse(event.target?.result as string)
                    // Basic validation
                    if (importedConfig.enabled !== undefined && importedConfig.policies?.rules) {
                      onConfigChange(importedConfig)
                      // Also save to localStorage
                      localStorage.setItem('shieldflow_config', JSON.stringify(importedConfig))
                      alert('Configuration imported successfully!')
                    } else {
                      alert('Invalid configuration format')
                    }
                  } catch {
                    alert('Failed to parse configuration file')
                  }
                }
                reader.readAsText(file)
                // Reset input
                e.target.value = ''
              }}
            />
          </label>
        </div>
      </div>

      {/* Restart Onboarding */}
      <div className="card">
        <h2 className="text-lg font-medium text-white mb-4">Onboarding</h2>
        <p className="text-sm text-zinc-400 mb-4">Restart the onboarding tour to learn about ShieldFlow features.</p>
        <button 
          onClick={onRestartOnboarding}
          className="btn btn-secondary flex items-center gap-2"
        >
          <Icons.Refresh /> Restart Onboarding
        </button>
      </div>
    </div>
  )
}

// ========== Confirmation Panel Component ==========
function ConfirmationPanel({ queue, onApprove, onDeny, onShowToast }: { 
  queue: DecisionEntry[]
  onApprove: (id: string) => void
  onDeny: (id: string) => void
  onShowToast: (message: string, type: ToastType) => void
}) {
  if (queue.length === 0) {
    return null
  }

  const handleApprove = (id: string) => {
    onApprove(id)
    onShowToast('Action approved', 'success')
  }

  const handleDeny = (id: string) => {
    onDeny(id)
    onShowToast('Action denied', 'error')
  }

  return (
    <div className="fixed right-0 top-0 h-full w-80 shadow-xl z-40 overflow-y-auto" style={{ backgroundColor: 'var(--bg-secondary)', borderLeft: '1px solid var(--border-color)' }}>
      <div className="p-4" style={{ borderBottom: '1px solid var(--border-color)' }}>
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <span className="text-amber-400"><Icons.AlertTriangle /></span>
          Pending Confirmations
          <span className="ml-auto bg-amber-500/20 text-amber-400 text-xs px-2 py-0.5 rounded-full">
            {queue.length}
          </span>
        </h2>
        <p className="text-sm text-zinc-400 mt-1">Review and respond to these requests</p>
      </div>
      <div className="p-4 space-y-3">
        {queue.map((item) => (
          <div key={item.entry_id} className="card p-3">
            <div className="flex items-center gap-2 mb-2">
              <code className="code text-xs">{item.tool_name}</code>
              <span className={`badge ${decisionColors[item.decision].bg} ${decisionColors[item.decision].text}`}>
                {item.decision}
              </span>
            </div>
            <p className="text-sm text-zinc-400 mb-3 line-clamp-2">{item.reason}</p>
            <div className="flex gap-2">
              <button 
                onClick={() => handleApprove(item.entry_id)}
                className="btn btn-primary flex-1 text-xs py-1.5"
              >
                Approve
              </button>
              <button 
                onClick={() => handleDeny(item.entry_id)}
                className="btn btn-danger flex-1 text-xs py-1.5"
              >
                Deny
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// Policies View
function PoliciesView({ config, onConfigChange, onShowToast }: { config: ShieldFlowConfig, onConfigChange: (c: ShieldFlowConfig) => void, onShowToast: (message: string, type: ToastType) => void }) {
  const [showModal, setShowModal] = useState(false)
  const [editingRule, setEditingRule] = useState<PolicyRule | undefined>()
  const [loadingRuleId, setLoadingRuleId] = useState<string | null>(null)
  const [deleteConfirmRule, setDeleteConfirmRule] = useState<PolicyRule | null>(null)

  const handleSaveRule = async (rule: PolicyRule) => {
    setLoadingRuleId(rule.id)
    try {
      await savePolicyRule(rule)
      const rules = config.policies.rules.some(r => r.id === rule.id)
        ? config.policies.rules.map(r => r.id === rule.id ? rule : r)
        : [...config.policies.rules, rule]
      onConfigChange({ ...config, policies: { ...config.policies, rules } })
      setShowModal(false)
      setEditingRule(undefined)
      onShowToast(rule.id ? 'Policy rule updated successfully' : 'Policy rule created successfully', 'success')
    } catch {
      onShowToast('Failed to save policy rule', 'error')
    } finally {
      setLoadingRuleId(null)
    }
  }

  const handleDeleteRule = async (ruleId: string) => {
    setLoadingRuleId(ruleId)
    try {
      await deletePolicyRule(ruleId)
      onConfigChange({ ...config, policies: { ...config.policies, rules: config.policies.rules.filter(r => r.id !== ruleId) } })
      onShowToast('Policy rule deleted successfully', 'success')
    } catch {
      onShowToast('Failed to delete policy rule', 'error')
    } finally {
      setLoadingRuleId(null)
    }
  }

  const sortedRules = [...config.policies.rules].sort((a, b) => b.priority - a.priority)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Policies</h1>
          <p className="text-zinc-400 text-sm">Manage security policy rules</p>
        </div>
        <button onClick={() => { setEditingRule(undefined); setShowModal(true) }} className="btn btn-primary">
          <Icons.Plus /> Add Rule
        </button>
      </div>

      <div className="card">
        <div className="flex items-center gap-4 mb-4">
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Default Action</label>
            <select value={config.policies.defaultAction} onChange={(e) => onConfigChange({ ...config, policies: { ...config.policies, defaultAction: e.target.value as Decision } })} className="input w-40">
              <option value="ALLOW">ALLOW</option>
              <option value="BLOCK">BLOCK</option>
              <option value="CONFIRM">CONFIRM</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Mode</label>
            <select value={config.policies.mode} onChange={(e) => onConfigChange({ ...config, policies: { ...config.policies, mode: e.target.value as any } })} className="input w-40">
              <option value="strict">Strict</option>
              <option value="moderate">Moderate</option>
              <option value="permissive">Permissive</option>
            </select>
          </div>
        </div>
      </div>

      <div className="space-y-3">
        {sortedRules.map((rule) => (
          <div key={rule.id} className="card flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className={`w-2 h-2 rounded-full ${rule.enabled ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
              <div>
                <div className="text-white font-medium">{rule.name}</div>
                <div className="text-sm text-zinc-500">
                  <code className="code">{rule.toolPattern}</code>
                  <span className="mx-2">→</span>
                  <span className={`badge ${decisionColors[rule.action].bg} ${decisionColors[rule.action].text}`}>{rule.action}</span>
                  <span className="ml-2 text-zinc-600">priority: {rule.priority}</span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button 
                onClick={() => { setEditingRule(rule); setShowModal(true) }} 
                className="btn btn-ghost text-zinc-400 hover:text-white"
                disabled={loadingRuleId !== null}
              >
                Edit
              </button>
              <button 
                onClick={() => setDeleteConfirmRule(rule)} 
                className="btn btn-ghost text-red-400 hover:text-red-300"
                disabled={loadingRuleId !== null}
              >
                {loadingRuleId === rule.id ? <Icons.Spinner /> : <Icons.Trash />}
              </button>
            </div>
          </div>
        ))}
        {sortedRules.length === 0 && (
          <div className="card text-center py-8">
            <p className="text-zinc-500">No policy rules configured. Add one to get started.</p>
          </div>
        )}
      </div>

      {showModal && (
        <PolicyRuleModal 
          rule={editingRule} 
          onSave={handleSaveRule} 
          onClose={() => { setShowModal(false); setEditingRule(undefined) }} 
        />
      )}

      {/* Delete Confirmation Dialog */}
      {deleteConfirmRule && (
        <div className="modal-overlay" onClick={() => setDeleteConfirmRule(null)}>
          <div className="modal max-w-sm" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-red-500/15 flex items-center justify-center">
                <Icons.AlertTriangle />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">Delete Policy Rule</h2>
                <p className="text-sm text-zinc-400">This action cannot be undone</p>
              </div>
            </div>
            <p className="text-zinc-300 mb-6">
              Are you sure you want to delete the rule <span className="text-white font-medium">"{deleteConfirmRule.name}"</span>?
            </p>
            <div className="flex gap-3">
              <button 
                onClick={() => setDeleteConfirmRule(null)} 
                className="btn btn-secondary flex-1"
              >
                Cancel
              </button>
              <button 
                onClick={() => {
                  const ruleId = deleteConfirmRule.id
                  setDeleteConfirmRule(null)
                  handleDeleteRule(ruleId)
                }} 
                className="btn btn-danger flex-1"
                disabled={loadingRuleId !== null}
              >
                {loadingRuleId === deleteConfirmRule.id ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Main App export with Error Boundary
export default function App() {
  return (
    <ErrorBoundary>
      <AppContent />
    </ErrorBoundary>
  )
}

// Main App
type View = 'dashboard' | 'settings' | 'policies'

function AppContent() {
  const [currentView, setCurrentView] = useState<View>('dashboard')
  const [data, setData] = useState<any>(null)
  const [config, setConfig] = useState<ShieldFlowConfig | null>(null)
  const [realtimeMetrics, setRealtimeMetrics] = useState<RealtimeMetrics>({ requestsPerMinute: 0, decisionsPerMinute: { allow: 0, block: 0, confirm: 0 }, activeSessions: 0, queueDepth: 0, uptime: 0 })
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [loading, setLoading] = useState(true)
  const [toasts, setToasts] = useState<Toast[]>([])
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [showKeyboardShortcuts, setShowKeyboardShortcuts] = useState(false)
  
  // Theme hook
  const { theme, toggleTheme } = useTheme()
  
  // Dashboard filters hook (URL persistence)
  const dashboardFilters = useDashboardFilters()

  // Keyboard shortcuts handler
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if user is typing in an input field
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement) {
        return
      }

      // Don't trigger shortcuts when modals are open (except Escape which closes them)
      if (e.key === 'Escape') {
        if (showKeyboardShortcuts) {
          setShowKeyboardShortcuts(false)
          return
        }
        return // Let modals handle their own Escape
      }

      switch (e.key) {
        case '?':
          setShowKeyboardShortcuts(prev => !prev)
          break
        case 'r':
        case 'R':
          if (currentView === 'dashboard') {
            handleRefresh()
          }
          break
        case '1':
          setCurrentView('dashboard')
          break
        case '2':
          setCurrentView('policies')
          break
        case '3':
          setCurrentView('settings')
          break
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [currentView, showKeyboardShortcuts])

  const showToast = (message: string, type: ToastType) => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 4000)
  }

  const removeToast = (id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }

  // Handlers for confirmation queue (CONFIRM decisions)
  const handleApprove = async (entryId: string) => {
    // In a real app, this would call an API to approve the action
    // For now, we just remove it from the queue
    setData((prev: typeof data) => ({
      ...prev,
      queue: prev.queue.filter((item: DecisionEntry) => item.entry_id !== entryId)
    }))
  }

  const handleDeny = async (entryId: string) => {
    // In a real app, this would call an API to deny the action
    // For now, we just remove it from the queue
    setData((prev: typeof data) => ({
      ...prev,
      queue: prev.queue.filter((item: DecisionEntry) => item.entry_id !== entryId)
    }))
  }

  const handleRestartOnboarding = async () => {
    await resetOnboarding()
    setShowOnboarding(true)
  }

  const handleRefresh = async () => {
    setIsRefreshing(true)
    try {
      const dashboardData = await loadDashboardData()
      setData(dashboardData)
      setLastUpdated(new Date())
    } catch (error) {
      showToast('Failed to refresh dashboard data', 'error')
    } finally {
      setIsRefreshing(false)
    }
  }

  // Fetch real uptime
  useEffect(() => {
    const fetchUptime = async () => {
      try {
        const res = await fetch('/health/detailed')
        const json = await res.json()
        setRealtimeMetrics(prev => ({ ...prev, uptime: Math.floor(json.uptime_seconds || 0) }))
      } catch (e) { /* ignore */ }
    }
    fetchUptime()
    const interval = setInterval(fetchUptime, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    let metricsInterval: ReturnType<typeof setInterval> | null = null
    
    const init = async () => {
      const [dashboardData, configData, onboardingState] = await Promise.all([
        loadDashboardData(),
        loadConfig(),
        loadOnboardingState()
      ])
      setData(dashboardData)
      setConfig(configData)
      setShowOnboarding(!onboardingState.isComplete)
      setLoading(false)
      setLastUpdated(new Date())
      
      // Simulate other realtime metrics
      metricsInterval = setInterval(() => {
        setRealtimeMetrics(prev => ({
          ...prev,
          requestsPerMinute: Math.floor(Math.random() * 30) + 5,
          decisionsPerMinute: {
            allow: Math.floor(Math.random() * 20) + 10,
            block: Math.floor(Math.random() * 5),
            confirm: Math.floor(Math.random() * 3),
          },
          activeSessions: Math.floor(Math.random() * 8) + 1,
          queueDepth: Math.floor(Math.random() * 5),
        }))
      }, 5000)
    }
    
    init()
    
    return () => {
      if (metricsInterval) {
        clearInterval(metricsInterval)
      }
    }
  }, [])

  if (loading || !data || !config) {
    return (
      <div className="min-h-screen bg-[#0a0a0b] flex items-center justify-center">
        <div className="text-zinc-400">Loading ShieldFlow...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      {showOnboarding && <OnboardingModal onComplete={() => setShowOnboarding(false)} />}
      
      <div className="flex">
        {/* Sidebar */}
        <aside className="w-64 min-h-screen border-r border-[var(--border-color)] p-4" style={{ backgroundColor: 'var(--bg-secondary)' }}>
          <div className="flex items-center gap-3 mb-8 px-2">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/15 flex items-center justify-center">
              <Icons.Shield />
            </div>
            <div>
              <div className="text-white font-semibold">ShieldFlow</div>
              <div className="text-xs text-zinc-500">Security Dashboard</div>
            </div>
          </div>

          <nav className="space-y-1">
            <button onClick={() => setCurrentView('dashboard')} className={`nav-item w-full ${currentView === 'dashboard' ? 'active' : ''}`}>
              <Icons.Dashboard /> Dashboard
            </button>
            <button onClick={() => setCurrentView('policies')} className={`nav-item w-full ${currentView === 'policies' ? 'active' : ''}`}>
              <Icons.Policies /> Policies
            </button>
            <button onClick={() => setCurrentView('settings')} className={`nav-item w-full ${currentView === 'settings' ? 'active' : ''}`}>
              <Icons.Settings /> Settings
            </button>
          </nav>

          <div className="absolute bottom-4 left-4 w-56">
            <div className="card">
              <div className="flex items-center justify-between">
                <span className="text-sm text-zinc-400">Protection</span>
                <span className={`text-xs ${config.enabled ? 'text-emerald-400' : 'text-red-400'}`}>
                  {config.enabled ? 'Active' : 'Disabled'}
                </span>
              </div>
            </div>
          </div>

          <button 
            onClick={() => setShowKeyboardShortcuts(true)}
            className="absolute bottom-4 left-4 mt-2 flex items-center gap-2 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
            title="Keyboard shortcuts"
          >
            <Icons.Keyboard /> Press ? for help
          </button>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6 pb-20">
          {currentView === 'dashboard' && (
            <DashboardView 
              data={data} 
              realtimeMetrics={realtimeMetrics} 
              onRefresh={handleRefresh} 
              isRefreshing={isRefreshing} 
              lastUpdated={lastUpdated}
              filters={dashboardFilters}
            />
          )}
          {currentView === 'settings' && (
            <SettingsView 
              config={config} 
              onConfigChange={setConfig}
              theme={theme}
              onToggleTheme={toggleTheme}
              onRestartOnboarding={handleRestartOnboarding}
            />
          )}
          {currentView === 'policies' && <PoliciesView config={config} onConfigChange={setConfig} onShowToast={showToast} />}
        </main>

        {/* Confirmation Panel (for CONFIRM decisions) */}
        <ConfirmationPanel 
          queue={data?.queue || []} 
          onApprove={handleApprove}
          onDeny={handleDeny}
          onShowToast={showToast}
        />

        {/* Toast Notifications */}
        <ToastContainer toasts={toasts} onRemove={removeToast} />

        {/* Keyboard Shortcuts Help Modal */}
        {showKeyboardShortcuts && (
          <div className="modal-overlay" onClick={() => setShowKeyboardShortcuts(false)}>
            <div className="modal max-w-md" onClick={e => e.stopPropagation()}>
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-lg font-semibold text-white">Keyboard Shortcuts</h2>
                <button onClick={() => setShowKeyboardShortcuts(false)} className="text-zinc-500 hover:text-white">
                  <Icons.X />
                </button>
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Show keyboard shortcuts</span>
                  <kbd className="kbd">?</kbd>
                </div>
                <div className="flex items-center justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Refresh dashboard</span>
                  <kbd className="kbd">r</kbd>
                </div>
                <div className="flex items-center justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Go to Dashboard</span>
                  <kbd className="kbd">1</kbd>
                </div>
                <div className="flex items-center justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Go to Policies</span>
                  <kbd className="kbd">2</kbd>
                </div>
                <div className="flex items-center justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Go to Settings</span>
                  <kbd className="kbd">3</kbd>
                </div>
                <div className="flex items-center justify-between py-2">
                  <span className="text-zinc-400">Close modal / Cancel</span>
                  <kbd className="kbd">Esc</kbd>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
