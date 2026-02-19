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
              <th>Reason</th>
              <th>Trust</th>
            </tr>
          </thead>
          <tbody>
            {blockedActions.map((entry) => (
              <tr key={entry.entry_id}>
                <td>{new Date(entry.timestamp).toLocaleString()}</td>
                <td>{entry.tool_name}</td>
                <td>{entry.reason}</td>
                <td>{entry.trigger_trust}</td>
              </tr>
            ))}
            {blockedActions.length === 0 ? (
              <tr>
                <td colSpan={4}>No blocked actions in current window.</td>
              </tr>
            ) : null}
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
