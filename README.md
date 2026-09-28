# Platform API

Shared lead-capture + notification backend for the site portfolio.
One Render free-tier service serves every site; frontends are static
(Cloudflare Pages) and POST here.

## Endpoints

- `GET /health` — liveness probe
- `POST /api/v1/leads` — `{site_id, name, email, business?, domain?, source?}` → `{ok, lead_id}`
- `POST /api/v1/beta` — `{site_id, lead_id}` → `{ok}`
- `GET /api/v1/stats?site_id=...` — `{leads, beta_optins}`

## Env vars

- `SITES_CONFIG` — JSON map of `site_id` → `{name, notify_email, from}`.
- `RESEND_API_KEY` — enables email notifications (fail-open without it).
- `RATE_LIMIT_PER_MIN` — per-IP POST throttle (default 30).
- `PORT` — set by the host; binds `0.0.0.0` when present.

## Notes

- Stdlib only. JSONL files per site under `data/` are a convenience —
  the host disk is ephemeral. The Resend notification email is the
  durable record of each lead.
- Deploy: Render Blueprint via `render.yaml` (free plan).
