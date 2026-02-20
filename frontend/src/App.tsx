import { Link, Navigate, Route, Routes } from 'react-router-dom'
import { useEffect, useState } from 'react'
import './App.css'
import { loadDashboardData } from './api'
import type { DashboardData } from './types'

function LandingPage() {
  return (
    <main className="page landing">
      <section className="hero card">
        <p className="kicker">ShieldFlow Demo</p>
        <h1>Protect tool-enabled AI workflows with policy-driven decisions</h1>
        <p>
          ShieldFlow evaluates every action before execution, blocks risky operations,
          and surfaces transparent reasoning for operators.
        </p>
        <div className="actions">
          <Link to="/dashboard" className="button primary">
            Open Dashboard
          </Link>
          <a href="/dashboard/api/decisions" className="button secondary">
            View Raw Decisions API
          </a>
        </div>
      </section>
    </main>
  )
}

function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null)

  useEffect(() => {
    void loadDashboardData().then(setData)
  }, [])

  if (!data) {
    return <main className="page"><p>Loading dashboard…</p></main>
  }

  const { decisions, blockedActions, queue, metrics, source, todo } = data

  const getDecisionBadge = (decision: string) => {
    const classes: Record<string, string> = {
      BLOCK: 'badge block',
      ALLOW: 'badge allow',
      CONFIRM: 'badge confirm',
    }
    return classes[decision] || 'badge'
  }

  const getTrustBadge = (trust: string) => {
    const classes: Record<string, string> = {
      OWNER: 'trust owner',
      USER: 'trust user',
      SYSTEM: 'trust system',
      AGENT: 'trust agent',
      TOOL: 'trust tool',
      NONE: 'trust none',
    }
    return classes[trust] || 'trust'
  }

  return (
    <main className="page dashboard">
      <header className="topbar">
        <h1>ShieldFlow Dashboard</h1>
        <Link to="/" className="button secondary">Back to Landing</Link>
      </header>

      <p className={`status ${source === 'live-api' ? 'live' : 'fallback'}`}>
        Data source: <strong>{source === 'live-api' ? 'Live backend endpoints' : 'Mock fallback state'}</strong>
        {todo ? ` — ${todo}` : ''}
      </p>

      <section className="grid summary">
        <article className="card">
          <h2>Recent Decisions</h2>
          <p className="metric">{decisions.length}</p>
          <small>Last 20 records from /dashboard/api/decisions</small>
        </article>

        <article className="card">
          <h2>Risk & Anomaly Summary</h2>
          <ul>
            <li>Blocked: {metrics.decisions.block_total}</li>
            <li>Confirm required: {metrics.decisions.confirm_total}</li>
            <li>Sessions at risk: {metrics.anomaly?.sessions_at_risk ?? 0}</li>
          </ul>
        </article>

        <article className="card">
          <h2>Confirmation Queue</h2>
          <p className="metric">{queue.length}</p>
          <small>Pending reviews from /dashboard/api/queue</small>
        </article>
      </section>

      <section className="card">
        <h2>Blocked Actions</h2>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Tool</th>
              <th>Decision</th>
              <th>Trust</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {blockedActions.map((entry) => (
              <tr key={entry.entry_id}>
                <td>{new Date(entry.timestamp).toLocaleString()}</td>
                <td><code>{entry.tool_name}</code></td>
                <td><span className={getDecisionBadge(entry.decision)}>{entry.decision}</span></td>
                <td><span className={getTrustBadge(entry.trigger_trust)}>{entry.trigger_trust}</span></td>
                <td>{entry.reason}</td>
              </tr>
            ))}
            {blockedActions.length === 0 ? (
              <tr>
                <td colSpan={5}>No blocked actions in current window.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2>Confirmation Queue</h2>
        <p className="help-text">Actions pending operator confirmation before execution.</p>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Tool</th>
              <th>Decision</th>
              <th>Trust</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {queue.map((entry) => (
              <tr key={entry.entry_id}>
                <td>{new Date(entry.timestamp).toLocaleString()}</td>
                <td><code>{entry.tool_name}</code></td>
                <td><span className={getDecisionBadge(entry.decision)}>{entry.decision}</span></td>
                <td><span className={getTrustBadge(entry.trigger_trust)}>{entry.trigger_trust}</span></td>
                <td>{entry.reason}</td>
              </tr>
            ))}
            {queue.length === 0 ? (
              <tr>
                <td colSpan={5}>No pending confirmations.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2>Recent Decisions</h2>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Tool</th>
              <th>Decision</th>
              <th>Trust</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {decisions.map((entry) => (
              <tr key={entry.entry_id}>
                <td>{new Date(entry.timestamp).toLocaleString()}</td>
                <td><code>{entry.tool_name}</code></td>
                <td><span className={getDecisionBadge(entry.decision)}>{entry.decision}</span></td>
                <td><span className={getTrustBadge(entry.trigger_trust)}>{entry.trigger_trust}</span></td>
                <td>{entry.trigger_source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  )
}

function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App
