#!/usr/bin/env python3
"""AI-agent access check for the company-two site. Stdlib only.

Answers one question: which known AI agents/crawlers CAN reach a site's
homepage — robots.txt posture plus a real fetch with each agent's
user-agent, run in parallel.

Ported from the Checklane audit engine (workspace/checklane/audit.py):
AGENT_UAS, AI_CRAWLER_TOKENS, normalize_domain, _assert_public_host,
_SafeRedirectHandler, fetch, parse_robots_ai_posture, challenge detection.

Read-only fetches of the submitted domain only. SSRF-guarded: the target
must resolve to public addresses, and redirects are re-checked.

HONESTY: this measures whether agents can LOAD the homepage, not whether
they are visiting now, and blocking a training crawler does NOT block AI
shopping (browser-driving agents buy through normal checkout).

Public entry point:
    check_agent_access(domain) -> dict   # JSON-serializable
Raises ValueError on invalid input.
"""

import concurrent.futures
import ipaddress
import re
import socket
import time
import urllib.parse
import urllib.request
import urllib.error

VERSION = "1.0.0"
ROBOTS_TIMEOUT = 6
FETCH_TIMEOUT = 8
MAX_BODY = 200_000  # we only need status + title + challenge markers

CHECK_UA = ("AgentAccessCheck/1.0 "
            "(+https://adjkimm.github.io/keystone-site-staging/)")

# slug -> display info. Order is fixed: the UI renders in this order.
AGENTS = [
    {"id": "gptbot", "name": "GPTBot", "kind": "Training crawler",
     "ua": "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
     "blurb": "Crawls the web to train OpenAI's models.",
     "token": "gptbot"},
    {"id": "oai-searchbot", "name": "OAI-SearchBot", "kind": "Search fetcher",
     "ua": "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/bot.html)",
     "blurb": "Fetches pages for ChatGPT's search answers.",
     "token": "oai-searchbot"},
    {"id": "claudebot", "name": "ClaudeBot", "kind": "Training crawler",
     "ua": "Mozilla/5.0 (compatible; ClaudeBot/1.0)",
     "blurb": "Crawls the web to train Anthropic's models.",
     "token": "claudebot"},
    {"id": "claude-searchbot", "name": "Claude-SearchBot",
     "kind": "Search fetcher",
     "ua": "Mozilla/5.0 (compatible; Claude-SearchBot/1.0)",
     "blurb": "Fetches pages for Claude's search answers.",
     "token": "claude-searchbot"},
    {"id": "ccbot", "name": "CCBot", "kind": "Dataset crawler",
     "ua": "CCBot/2.0 (https://commoncrawl.org/faq/)",
     "blurb": "Builds the open Common Crawl dataset many models train on.",
     "token": "ccbot"},
    {"id": "perplexitybot", "name": "PerplexityBot",
     "kind": "Discovery crawler",
     "ua": "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai)",
     "blurb": "Finds pages for Perplexity's answers.",
     "token": "perplexitybot"},
    {"id": "chatgpt-user", "name": "ChatGPT-User",
     "kind": "On-demand fetcher",
     "ua": "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot.html)",
     "blurb": "Fetches a page when a ChatGPT user asks about it.",
     "token": "chatgpt-user"},
    {"id": "googleother", "name": "GoogleOther", "kind": "AI crawler",
     "ua": "Mozilla/5.0 (compatible; GoogleOther/1.0)",
     "blurb": "Google's crawler for AI features.",
     "token": "googleother"},
    {"id": "google-agent", "name": "Google-Agent",
     "kind": "Agentic fetcher",
     "ua": "Mozilla/5.0 (compatible; Google-Agent/1.0)",
     "blurb": "Google's agent-mode fetcher. Does not honor robots.txt.",
     "token": None},  # deliberately absent: claiming a robots verdict would be false
]

AI_CRAWLER_TOKENS = [
    "gptbot", "oai-searchbot", "google-extended", "googleother",
    "claudebot", "claude-searchbot", "ccbot",
    "perplexitybot", "chatgpt-user", "anthropic-ai", "cohere-ai",
    "bytespider", "amazonbot",
]

BLOCKED_STATUSES = {401, 403, 407, 429}
CHALLENGE_MARKERS = [
    "captcha", "robot or human", "are you a robot", "perimeterx",
    "datadome", "cloudflare", "cf-challenge", "just a moment",
    "access denied", "request blocked",
]


def normalize_domain(raw):
    """Turn user input into a bare hostname. Raises ValueError if invalid."""
    raw = (raw or "").strip().lower()
    if not raw:
        raise ValueError("enter a domain")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urllib.parse.urlsplit(raw)
    except Exception:
        raise ValueError("could not parse domain")
    host = parts.hostname or ""
    host = host.strip().strip(".")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,250}[a-z0-9])?", host):
        raise ValueError("invalid hostname")
    if "." not in host:
        raise ValueError("not a public domain")
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        raise ValueError("IP addresses are not accepted")
    if host in ("localhost",) or host.endswith(".local") or host.endswith(
            ".internal"):
        raise ValueError("local hostnames are not accepted")
    _assert_public_host(host)
    return host


def _assert_public_host(host):
    """SSRF guard: host must resolve, all addresses globally routable."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise ValueError("could not resolve host")
    ips = {info[4][0] for info in infos}
    if not ips:
        raise ValueError("could not resolve host")
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("unresolvable address")
        if not addr.is_global:
            raise ValueError("host does not resolve to a public address")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects whose target host fails the SSRF guard."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(
            urllib.parse.urljoin(req.full_url, newurl))
        host = (target.hostname or "").strip().strip(".")
        if not host:
            raise urllib.error.URLError("redirect to invalid host blocked")
        try:
            _assert_public_host(host)
        except ValueError as e:
            raise urllib.error.URLError("redirect blocked: %s" % e)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirectHandler)


def _fetch(url, ua, timeout):
    """GET url. Returns dict(status, body, error). Never raises."""
    req = urllib.request.Request(url, headers={
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BODY + 1)
            body = raw[:MAX_BODY].decode("utf-8", errors="replace")
            return {"status": resp.status, "body": body, "error": None}
    except Exception as e:
        return {"status": None, "body": "", "error": str(e)[:120]}


def _parse_robots_ai_posture(robots_body):
    """Return {token: 'blocked'|'unspecified'} for AI crawler tokens.

    A token counts as blocked only when it (or a wildcard group) is
    disallowed from "/". Anything else is 'unspecified'.
    """
    posture = {t: "unspecified" for t in AI_CRAWLER_TOKENS}
    if not robots_body:
        return posture
    groups = []
    cur_uas, cur_dis = [], []
    for line in robots_body.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field, value = field.strip().lower(), value.strip()
        if field == "user-agent":
            if cur_dis:
                groups.append((cur_uas, cur_dis))
                cur_uas, cur_dis = [], []
            cur_uas.append(value.lower())
        elif field == "disallow":
            cur_dis.append(value)
    if cur_uas or cur_dis:
        groups.append((cur_uas, cur_dis))
    for uas, dis in groups:
        blocked_all = any(d.strip() == "/" for d in dis)
        if not blocked_all:
            continue
        for ua in uas:
            for token in AI_CRAWLER_TOKENS:
                if token == ua or ua == "*":
                    posture[token] = "blocked"
    return posture


def _looks_like_challenge(body):
    """Challenge pages are small AND mention challenge markers."""
    if len(body) > 50_000:
        return None
    low = body[:50_000].lower()
    return next((m for m in CHALLENGE_MARKERS if m in low), None)


def _verdict_for(agent, http, robots_posture):
    """Return (verdict, note). Verdict: can_reach | blocked | unknown."""
    token = agent["token"]
    robots_says = (robots_posture.get(token) if token else "unspecified")

    if http["status"] is None:
        if robots_says == "blocked":
            return ("blocked",
                    "Your robots.txt tells it to stay out. (The live fetch failed.)")
        return ("unknown", "No clear answer — the request timed out.")

    status = http["status"]
    if status in BLOCKED_STATUSES or status >= 400:
        return ("blocked",
                "Your server or firewall stops it (HTTP %d)." % status)
    hit = _looks_like_challenge(http["body"])
    if hit:
        return ("blocked",
                "Gets a bot-check page instead of your content.")
    if robots_says == "blocked":
        return ("blocked",
                "Your robots.txt tells it to stay out.")
    return ("can_reach", "Can load your homepage today.")


def check_agent_access(domain):
    """Run the access check. Returns a JSON-serializable dict."""
    started = time.time()
    host = normalize_domain(domain)
    base = "https://" + host

    jobs = {"__robots__": (base + "/robots.txt", CHECK_UA, ROBOTS_TIMEOUT)}
    for a in AGENTS:
        jobs[a["id"]] = (base + "/", a["ua"], FETCH_TIMEOUT)

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        future_to_key = {
            pool.submit(_fetch, url, ua, timeout): key
            for key, (url, ua, timeout) in jobs.items()
        }
        for fut in concurrent.futures.as_completed(future_to_key):
            results[future_to_key[fut]] = fut.result()

    robots_body = results.get("__robots__", {}).get("body", "")
    posture = _parse_robots_ai_posture(robots_body)

    agents = []
    for a in AGENTS:
        verdict, note = _verdict_for(a, results.get(a["id"], {}), posture)
        agents.append({
            "id": a["id"],
            "name": a["name"],
            "kind": a["kind"],
            "blurb": a["blurb"],
            "verdict": verdict,   # can_reach | blocked | unknown
            "note": note,
            "http_status": results.get(a["id"], {}).get("status"),
        })

    summary = {
        "can_reach": sum(1 for a in agents if a["verdict"] == "can_reach"),
        "blocked": sum(1 for a in agents if a["verdict"] == "blocked"),
        "unknown": sum(1 for a in agents if a["verdict"] == "unknown"),
        "total": len(agents),
    }
    return {
        "domain": host,
        "checked_at": int(time.time()),
        "elapsed_ms": int((time.time() - started) * 1000),
        "what_this_measures": ("Which AI agents can load the homepage. "
                               "Not which agents are visiting now."),
        "agents": agents,
        "summary": summary,
    }
