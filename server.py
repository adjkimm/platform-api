#!/usr/bin/env python3
"""
Shared platform API for the site portfolio. Stdlib only.

One service serves every site's lead capture + notification layer:

  GET  /health                    -> liveness probe
  POST /api/v1/leads              -> capture lead, returns lead_id
  POST /api/v1/beta               -> record beta/waitlist opt-in {lead_id}
  GET  /api/v1/stats?site_id=...  -> counters for one site

Request bodies include a `site_id` that selects per-site config
(name, notify email, sender identity) from the SITES_CONFIG env var:

  SITES_CONFIG='{"checklane":{"name":"Checklane",
    "notify_email":"adjkimm@gmail.com",
    "from":"Checklane <onboarding@resend.dev>"}}'

Lead notification goes to the site's notify email via Resend
(RESEND_API_KEY). Best-effort: failures never block the signup, and the
notification email itself is the durable record — the free hosting tier's
disk is ephemeral, so per-site JSONL files are a convenience, not the
source of truth. All events also log as PII-free JSON lines to stdout.

Run:  python3 server.py [port]      (default 8080, or $PORT)
"""

import json
import os
import re
import time
import uuid
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import agent_access
import ed25519
import keystone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
try:
    SITES_CONFIG = json.loads(os.environ.get("SITES_CONFIG", "{}"))
except Exception:
    SITES_CONFIG = {}

# Light abuse throttle: max POSTs per IP per rolling minute.
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "30"))
_rate_buckets = {}

# The agent-access check fans out to ~10 outbound fetches per request,
# so it gets its own tighter bucket: max checks per IP per rolling minute.
ACCESS_CHECK_PER_MIN = int(os.environ.get("ACCESS_CHECK_PER_MIN", "6"))
_access_buckets = {}

# The Keystone verifier is a cheap local check; builders hammer it while
# testing, so it gets its own 60/min/IP bucket (exempt from the global
# POST bucket below).
VERIFY_PER_MIN = int(os.environ.get("VERIFY_PER_MIN", "60"))
_verify_buckets = {}


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def append_jsonl(path, obj):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    return rows


def log_event(kind, obj):
    try:
        print(json.dumps({"event": kind, "ts": int(time.time()), **obj}),
              flush=True)
    except Exception:
        pass


def site_config(site_id):
    cfg = SITES_CONFIG.get(site_id)
    if not isinstance(cfg, dict):
        return None
    return cfg


def site_file(site_id, kind):
    safe = re.sub(r"[^a-z0-9_-]", "", site_id.lower()) or "unknown"
    return os.path.join(DATA_DIR, "%s-%s.jsonl" % (kind, safe))


def check_rate(ip):
    now = time.time()
    bucket = _rate_buckets.get(ip, [])
    bucket = [t for t in bucket if now - t < 60]
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        _rate_buckets[ip] = bucket
        return False
    bucket.append(now)
    _rate_buckets[ip] = bucket
    return True


def check_access_rate(ip):
    now = time.time()
    bucket = _access_buckets.get(ip, [])
    bucket = [t for t in bucket if now - t < 60]
    if len(bucket) >= ACCESS_CHECK_PER_MIN:
        _access_buckets[ip] = bucket
        return False
    bucket.append(now)
    _access_buckets[ip] = bucket
    return True


def check_verify_rate(ip):
    now = time.time()
    bucket = _verify_buckets.get(ip, [])
    bucket = [t for t in bucket if now - t < 60]
    if len(bucket) >= VERIFY_PER_MIN:
        _verify_buckets[ip] = bucket
        return False
    bucket.append(now)
    _verify_buckets[ip] = bucket
    return True


def keystone_well_known_path(issuer_id, filename):
    """Resolve a well-known issuer document to a file on disk."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", issuer_id or ""):
        return None
    if filename not in ("keys.json", "revocations.json"):
        return None
    path = os.path.join(HERE, "keystone", filename)
    return path if os.path.exists(path) else None


def send_notification(cfg, subject, body):
    """Email the site owner about a lead/beta event via Resend.

    Best-effort: never raises, never blocks the signup.
    """
    to = cfg.get("notify_email", "")
    if not RESEND_API_KEY or not to:
        log_event("notify_skipped", {
            "reason": "no RESEND_API_KEY" if not RESEND_API_KEY
            else "no notify_email"})
        return
    try:
        payload = json.dumps({
            "from": cfg.get("from", "Platform <onboarding@resend.dev>"),
            "to": [to],
            "subject": subject,
            "text": body,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.resend.com/emails", data=payload,
            headers={"Authorization": "Bearer " + RESEND_API_KEY,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
        log_event("notify_sent", {"subject": subject})
    except Exception as e:
        log_event("notify_failed", {"error": str(e)[:200]})


def notify_lead(cfg, site_id, lead):
    name = cfg.get("name", site_id)
    when = time.strftime("%Y-%m-%d %H:%M PT", time.localtime(lead["ts"]))
    lines = [
        "New %s lead — %s" % (name, when),
        "",
        "Name:     %s" % lead.get("name", ""),
        "Email:    %s" % lead.get("email", ""),
    ]
    if lead.get("business"):
        lines.append("Business: %s" % lead["business"])
    if lead.get("domain"):
        lines.append("Domain:   %s" % lead["domain"])
    if lead.get("source"):
        lines.append("Source:   %s" % lead["source"])
    lines.append("Lead ID:  %s" % lead["id"])
    send_notification(cfg, "New %s lead: %s" % (
        name, lead.get("business") or lead.get("email", "")), "\n".join(lines))


def notify_beta(cfg, site_id, lead):
    name = cfg.get("name", site_id)
    body = "\n".join([
        "Beta/waitlist opt-in for lead %s:" % lead["id"],
        "",
        "Name:     %s" % lead.get("name", ""),
        "Email:    %s" % lead.get("email", ""),
        "Business: %s" % lead.get("business", ""),
    ])
    send_notification(cfg, "%s beta opt-in: %s" % (
        name, lead.get("business") or lead.get("email", "")), body)


class Handler(BaseHTTPRequestHandler):
    server_version = "PlatformAPI/1.0"

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # The static sites call this API cross-origin (e.g. GitHub Pages ->
        # Render), so every API response carries permissive CORS headers.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _cors_preflight(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_OPTIONS(self):
        self._cors_preflight()

    def _json(self, code, obj):
        self._send(code, json.dumps(obj))

    def _not_found(self):
        self._json(404, {"error": "not found"})

    def _read_body(self, limit=65536):
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > limit:
            return None
        return self.rfile.read(n)

    def log_message(self, fmt, *args):
        pass

    def _client_ip(self):
        fwd = self.headers.get("X-Forwarded-For", "")
        return (fwd.split(",")[0].strip() if fwd
                else self.client_address[0])

    # -- routing ------------------------------------------------------ #
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query or "")

        if path == "/health":
            return self._json(200, {"ok": True, "ts": int(time.time())})

        if path == "/api/agent-access":
            if not check_access_rate(self._client_ip()):
                return self._json(429, {"error": "rate limited, try again soon"})
            domain = (qs.get("domain") or [""])[0]
            try:
                result = agent_access.check_agent_access(domain)
            except ValueError as e:
                return self._json(400, {"error": str(e)[:200]})
            except Exception:
                return self._json(502, {"error": "check failed, try again"})
            log_event("agent_access", {
                "domain": result["domain"],
                "ms": result["elapsed_ms"],
                "can_reach": result["summary"]["can_reach"],
                "blocked": result["summary"]["blocked"],
                "unknown": result["summary"]["unknown"],
            })
            return self._json(200, result)

        if path == "/api/issuers":
            host = self.headers.get("Host") or "platform-api-yf9l.onrender.com"
            base_url = "https://" + host
            return self._json(200, keystone.issuer_list(base_url))

        wk_prefix = keystone.WELL_KNOWN_BASE + "/issuers/"
        if path.startswith(wk_prefix):
            rest = path[len(wk_prefix):].split("/")
            if len(rest) == 2:
                fpath = keystone_well_known_path(rest[0], rest[1])
                if fpath:
                    with open(fpath, "rb") as f:
                        return self._send(200, f.read())
            return self._not_found()

        if path == "/api/v1/stats":
            site_id = (qs.get("site_id") or [""])[0].strip()
            if not site_config(site_id):
                return self._json(400, {"error": "unknown site_id"})
            leads = read_jsonl(site_file(site_id, "leads"))
            betas = read_jsonl(site_file(site_id, "beta"))
            beta_ids = {b.get("lead_id") for b in betas}
            return self._json(200, {
                "site_id": site_id,
                "leads": len(leads),
                "beta_optins": len(beta_ids),
            })

        return self._not_found()

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        # The Keystone verifier has its own 60/min/IP bucket and is
        # exempt from the global POST bucket.
        if path == "/api/verify":
            if not check_verify_rate(self._client_ip()):
                return self._json(429, {"error": "rate limited, try again soon"})
        elif not check_rate(self._client_ip()):
            return self._json(429, {"error": "rate limited, try again soon"})

        raw = self._read_body()
        if raw is None:
            return self._json(400, {"error": "missing or oversized body"})
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return self._json(400, {"error": "body must be JSON"})

        if path == "/api/verify":
            resp = keystone.verify_credential(data)
            log_event("verify", {
                "valid": resp["valid"],
                "reason": resp.get("reason"),
                "issuer": (resp.get("issuer") or {}).get("id"),
            })
            return self._json(200, resp)

        if path == "/api/v1/leads":
            site_id = str(data.get("site_id", "")).strip()
            cfg = site_config(site_id)
            if not cfg:
                return self._json(400, {"error": "unknown site_id"})
            name = str(data.get("name", "")).strip()
            email = str(data.get("email", "")).strip().lower()
            business = str(data.get("business", "")).strip()
            domain = str(data.get("domain", "")).strip().lower()
            source = str(data.get("source", "")).strip()[:120]
            errors = {}
            if len(name) < 2:
                errors["name"] = "please enter your name"
            if not EMAIL_RE.match(email):
                errors["email"] = "please enter a valid email address"
            if errors:
                return self._json(400, {"error": "invalid fields",
                                        "fields": errors})
            lead = {
                "id": uuid.uuid4().hex[:12],
                "ts": int(time.time()),
                "site_id": site_id,
                "name": name, "email": email,
                "business": business, "domain": domain,
                "source": source,
            }
            append_jsonl(site_file(site_id, "leads"), lead)
            log_event("lead", {"site_id": site_id, "id": lead["id"]})
            notify_lead(cfg, site_id, lead)
            return self._json(200, {"ok": True, "lead_id": lead["id"]})

        if path == "/api/v1/beta":
            site_id = str(data.get("site_id", "")).strip()
            cfg = site_config(site_id)
            if not cfg:
                return self._json(400, {"error": "unknown site_id"})
            lead_id = str(data.get("lead_id", "")).strip()
            leads = {l.get("id"): l
                     for l in read_jsonl(site_file(site_id, "leads"))}
            if not lead_id or lead_id not in leads:
                return self._json(400, {"error": "unknown lead_id"})
            append_jsonl(site_file(site_id, "beta"),
                         {"ts": int(time.time()), "lead_id": lead_id})
            log_event("beta", {"site_id": site_id, "lead_id": lead_id})
            notify_beta(cfg, site_id, leads[lead_id])
            return self._json(200, {"ok": True})

        return self._not_found()


def main():
    import sys
    ensure_data_dir()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(
        os.environ.get("PORT", 8080))
    host = "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"
    srv = ThreadingHTTPServer((host, port), Handler)
    print("Platform API: http://%s:%d/  sites=%s" % (
        host, port, sorted(SITES_CONFIG.keys())), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
