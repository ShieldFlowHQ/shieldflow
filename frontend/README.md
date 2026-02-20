# ShieldFlow Frontend Demo

Production-minded React + TypeScript + Vite demo slice for ShieldFlow.

## Included in this demo

- Landing page (`/`) with product value proposition and CTA to dashboard
- Dashboard shell (`/dashboard`) with:
  - Recent decisions summary
  - Risk/anomaly summary
  - Blocked actions table
- Live API wiring to:
  - `GET /dashboard/api/decisions`
  - `GET /dashboard/api/queue`
  - `GET /metrics/json`
- Graceful mock fallback when backend endpoints are unavailable
  - Includes explicit TODO marker in UI

## Local run

```bash
cd frontend
npm install
npm run dev
```

Open: <http://localhost:5173>

### Backend integration in local dev

Vite dev server proxies these paths to `http://localhost:8000`:

- `/dashboard`
- `/metrics`

So frontend fetch calls can stay same-origin (`/dashboard/api/*`, `/metrics/json`).

## Quality checks

```bash
npm run lint
npm run test
npm run build
```

## Screenshot-ready routes

- Landing: <http://localhost:5173/>
- Dashboard: <http://localhost:5173/dashboard>
- Decisions API (JSON): <http://localhost:5173/dashboard/api/decisions?n=20>
- Metrics JSON: <http://localhost:5173/metrics/json>
