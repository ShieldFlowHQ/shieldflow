import { mockDashboardData } from './mockData'
import type { DashboardData, DecisionEntry, MetricsSnapshot } from './types'

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
