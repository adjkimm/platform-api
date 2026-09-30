#!/usr/bin/env python3
"""Keystone credential issuance and verification — spec draft-01.

Implements the credential format, signing, and the four verification
checks from spec-draft-01.md:

    1. test_credential  — scope must be "test" in this draft
    2. signature        — Ed25519 over JCS-canonical JSON of all fields
                          except "sig", verified against the issuer's key
    3. not_expired      — exp is in the future
    4. not_revoked      — credential id (its "sig" value) is absent from
                          the issuer's signed revocation list, which must
                          itself be fresh (provisional: refreshed every
                          15 min, rejected if older than 24 h)

Stdlib only. Real Ed25519 (see ed25519.py) — not a mock.
"""

import base64
import json
import os
import time

import ed25519

HERE = os.path.dirname(os.path.abspath(__file__))

SPEC_VERSION = "draft-01"

# --- spec values (confirmed by owner 2026-09-30) ------------------------
SIG_ALG = "Ed25519"          # confirmed
CANONICALISATION = "JCS"     # RFC 8785, confirmed
REVOCATION_REFRESH_S = 15 * 60   # verifier refresh interval, confirmed
REVOCATION_MAX_AGE_S = 24 * 3600  # max revocation-list age, confirmed
DEMO_TTL_S = 48 * 3600       # demo credential lifetime, per brief
# -----------------------------------------------------------------------

WELL_KNOWN_BASE = "/.well-known/agent-identity/v1"

# Issuer registry. Public information only — no private keys here.
# NOTE: "keystone-test" and "acme-test" are internal test identifiers and
# will be renamed when the product name is chosen. During the test phase
# new issuers are added here manually; the spec's long-term design is key
# discovery from the issuer's own domain (see spec-draft-01.md).
ISSUERS = {
    "keystone-test": {
        "name": "Keystone test issuer",
        "key_id": "kt1-20260930",
        # base64url of the raw 32-byte Ed25519 public key. Filled in by
        # the key-generation step (see keystone/keys.json).
        "public_key": "T80zCoXqmXYr0ApVCkM3-3uCMbdB2nEJ9zKGmoSHTdE",
        "note": "Internal test identifier. Will be renamed when the "
                "product name is chosen.",
    },
    "acme-test": {
        "name": "ACME test issuer",
        "key_id": "acme1-20260930",
        # End-to-end issuer-flow test issuer (not a real builder).
        # Public key filled in by the keystone-issuer.py keygen step.
        "public_key": "YDSpAg08umy3dYDgxKSVKaaPaWhkCEfmsc4pN4SzLm4",
        "note": "End-to-end test issuer for the issuer toolkit flow. "
                "Not a real builder.",
    },
}

REQUIRED_TOP_FIELDS = {
    "agent": dict, "issuer": dict, "iat": int, "exp": int,
    "scope": str, "sig": str,
}


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(s):
    if not isinstance(s, str):
        raise ValueError("not a string")
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def canonical(obj):
    """JCS (RFC 8785) canonical JSON for this data profile.

    Credential values are only str, int, and nested dicts — no floats,
    no lone surrogates — so json.dumps with sorted keys, no whitespace,
    and UTF-8 output is JCS-conformant for everything this spec signs.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _shape_ok(cred):
    """Structural validation. Returns (ok, agent_echo, issuer_echo)."""
    agent_echo = {"id": "", "name": "", "operator": ""}
    issuer_echo = {"id": "", "name": ""}
    if not isinstance(cred, dict):
        return False, agent_echo, issuer_echo
    for field, typ in REQUIRED_TOP_FIELDS.items():
        if field not in cred:
            return False, agent_echo, issuer_echo
        v = cred[field]
        if typ is int:
            if not _is_int(v):
                return False, agent_echo, issuer_echo
        elif not isinstance(v, typ):
            return False, agent_echo, issuer_echo
    agent = cred["agent"]
    issuer = cred["issuer"]
    for f in ("id", "name", "operator"):
        if f not in agent or not isinstance(agent[f], str):
            return False, agent_echo, issuer_echo
    for f in ("id", "name"):
        if f not in issuer or not isinstance(issuer[f], str):
            return False, agent_echo, issuer_echo
    agent_echo = {"id": agent["id"], "name": agent["name"],
                  "operator": agent["operator"]}
    issuer_echo = {"id": issuer["id"], "name": issuer["name"]}
    return True, agent_echo, issuer_echo


def sign_credential(seed, agent, issuer_id, ttl_s=DEMO_TTL_S,
                    scope="test", now=None):
    """Sign a credential dict. Returns the complete credential."""
    now = int(now if now is not None else time.time())
    issuer = ISSUERS[issuer_id]
    body = {
        "agent": {"id": agent["id"], "name": agent["name"],
                  "operator": agent["operator"]},
        "issuer": {"id": issuer_id, "name": issuer["name"]},
        "iat": now,
        "exp": now + ttl_s,
        "scope": scope,
    }
    sig = ed25519.sign(canonical(body), seed)
    body["sig"] = b64u_encode(sig)
    return body


def _load_revocation_list(issuer_id):
    """Load and validate the issuer's revocation list from disk.

    Returns (doc_or_None, fresh_bool). Refreshes the in-memory cache if
    older than REVOCATION_REFRESH_S. The list is signed by the issuer;
    an invalid signature or a list older than REVOCATION_MAX_AGE_S is
    treated as unavailable (fail closed downstream).
    """
    now = time.time()
    cache = _load_revocation_list.__dict__.setdefault("cache", {})
    entry = cache.get(issuer_id)
    if entry and now - entry["loaded_at"] < REVOCATION_REFRESH_S:
        return entry["doc"], entry["fresh"]

    doc, fresh = None, False
    try:
        # Per-issuer revocation list first, then the legacy single file
        # (keystone-test, kept for the daily re-issue job).
        candidates = [
            os.path.join(HERE, "keystone", "revocations",
                         issuer_id + ".json"),
            os.path.join(HERE, "keystone", "revocations.json"),
        ]
        raw = None
        for path in candidates:
            try:
                with open(path, encoding="utf-8") as f:
                    candidate = json.load(f)
            except FileNotFoundError:
                continue
            if (isinstance(candidate, dict)
                    and candidate.get("issuer_id") == issuer_id):
                raw = candidate
                break
        if raw is None:
            raise FileNotFoundError
        if (isinstance(raw.get("revoked"), list)
                and _is_int(raw.get("issued_at"))
                and isinstance(raw.get("sig"), str)):
            issuer = ISSUERS.get(issuer_id)
            if issuer and issuer.get("public_key"):
                pk = b64u_decode(issuer["public_key"])
                body = {k: raw[k] for k in
                        ("issuer_id", "key_id", "issued_at", "revoked")}
                if ed25519.verify(b64u_decode(raw["sig"]),
                                  canonical(body), pk):
                    doc = raw
                    fresh = (now - raw["issued_at"]) < REVOCATION_MAX_AGE_S
    except Exception:
        doc, fresh = None, False
    cache[issuer_id] = {"loaded_at": now, "doc": doc, "fresh": fresh}
    return doc, fresh


def verify_credential(cred, now=None):
    """Verify a credential. Returns the /api/verify response dict."""
    now = now if now is not None else time.time()
    checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    ok, agent_echo, issuer_echo = _shape_ok(cred)
    if not ok:
        return {
            "valid": False,
            "reason": "malformed",
            "checks": {"test_credential": False, "signature": False,
                       "not_expired": False, "not_revoked": False},
            "issuer": issuer_echo,
            "agent": agent_echo,
            "checked_at": checked_at,
        }

    checks = {}
    checks["test_credential"] = (cred["scope"] == "test")

    # Signature. An unknown issuer has no key to verify against, so the
    # signature check fails (reason invalid_signature).
    sig_ok = False
    issuer = ISSUERS.get(cred["issuer"]["id"])
    if issuer and issuer.get("public_key"):
        try:
            pk = b64u_decode(issuer["public_key"])
            sig_bytes = b64u_decode(cred["sig"])
            body = {k: v for k, v in cred.items() if k != "sig"}
            sig_ok = (len(sig_bytes) == 64
                      and ed25519.verify(sig_bytes, canonical(body), pk))
        except Exception:
            sig_ok = False
    checks["signature"] = sig_ok

    checks["not_expired"] = cred["exp"] > now

    # Revocation. Credential id == its "sig" value (unique per credential).
    # Fail closed: a missing, invalid, or stale revocation list counts as
    # not_revoked=false (reason "revoked").
    revoked_ok = False
    doc, fresh = _load_revocation_list(cred["issuer"]["id"])
    if doc is not None and fresh:
        revoked_ids = {r.get("credential_id") for r in doc["revoked"]
                       if isinstance(r, dict)}
        revoked_ok = cred["sig"] not in revoked_ids
    checks["not_revoked"] = revoked_ok

    order = [("test_credential", "not_test_credential"),
             ("signature", "invalid_signature"),
             ("not_expired", "expired"),
             ("not_revoked", "revoked")]
    reason = next((r for c, r in order if not checks[c]), None)

    resp = {
        "valid": reason is None,
        "checks": checks,
        "issuer": issuer_echo,
        "agent": agent_echo,
        "checked_at": checked_at,
    }
    if reason is not None:
        resp["reason"] = reason
    return resp


def issuer_list(base_url):
    """Public issuer list for GET /api/issuers."""
    out = []
    for issuer_id, info in ISSUERS.items():
        out.append({
            "id": issuer_id,
            "name": info["name"],
            "key_id": info["key_id"],
            "keys_url": (base_url + WELL_KNOWN_BASE +
                         "/issuers/%s/keys.json" % issuer_id),
            "note": info.get("note", ""),
        })
    return {"issuers": out, "spec": SPEC_VERSION}
