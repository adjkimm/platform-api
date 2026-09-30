#!/usr/bin/env python3
"""Keystone issuer toolkit — spec draft-01.

Everything a builder needs to become an issuer, stdlib only:

    keygen   generate an Ed25519 keypair
    keydoc   emit the well-known issuer key document
    sign     sign a credential for one of your agents
    verify   verify a credential locally (same check order as /api/verify)
    revoke   add a credential to your revocation list and re-sign it

Run `keystone-issuer.py <subcommand> --help` for details.

Reuses ed25519.py (signing) and keystone.py (JCS canonicalisation,
base64url helpers) from this directory — no crypto is reimplemented here.
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ed25519
import keystone

DEFAULT_HOST = "platform-api-yf9l.onrender.com"
WELL_KNOWN = keystone.WELL_KNOWN_BASE + "/issuers/%s/%s"


def _warn(msg):
    print("warning: %s" % msg, file=sys.stderr)


def _load_key(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    seed = keystone.b64u_decode(doc["seed_b64u"])
    if len(seed) != 32:
        raise ValueError("bad seed in %s" % path)
    return doc, seed


def _http_get_json(url, timeout=10):
    req = urllib.request.Request(
        url, headers={"User-Agent": "keystone-issuer-toolkit/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


# ---------------------------------------------------------------- keygen

def cmd_keygen(args):
    seed = os.urandom(32)
    pub = ed25519.publickey(seed)
    key_id = args.key_id or ("kid-" + time.strftime("%Y%m%d"))
    doc = {
        "key_id": key_id,
        "seed_b64u": keystone.b64u_encode(seed),
        "public_key_b64u": keystone.b64u_encode(pub),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                    time.gmtime()),
        "note": "PRIVATE. Never commit, never share, never send over "
                "chat. The server never needs this file.",
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(args.out, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("wrote %s (mode 600)" % args.out)
    print("key_id:     %s" % key_id)
    print("public_key: %s" % doc["public_key_b64u"])
    print()
    print("KEEP THE PRIVATE FILE SECRET. Only the public key and key id "
          "ever leave this machine.")
    return 0


# ---------------------------------------------------------------- keydoc

def cmd_keydoc(args):
    keydoc, _seed = _load_key(args.key)
    revocations_url = args.revocations_url or (
        "https://%s" % args.host + WELL_KNOWN % (args.issuer_id,
                                                "revocations.json"))
    doc = {
        "issuer": {"id": args.issuer_id, "name": args.issuer_name},
        "keys": [{
            "key_id": keydoc["key_id"],
            "alg": "Ed25519",
            "public_key": keydoc["public_key_b64u"],
            "encoding": "base64url of raw 32-byte public key",
            "created_at": keydoc["created_at"],
        }],
        "revocations": revocations_url,
        "note": "Keystone test draft (spec draft-01). Working title; "
                "the product name is still to come.",
    }
    out = json.dumps(doc, indent=2) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print("wrote %s" % args.out)
    else:
        print(out, end="")
    print()
    print("Publish this at /.well-known/agent-identity/v1/issuers/%s/"
          "keys.json on your domain." % args.issuer_id)
    return 0


# ------------------------------------------------------------------ sign

def cmd_sign(args):
    _keydoc, seed = _load_key(args.key)
    now = int(time.time())
    body = {
        "agent": {"id": args.agent_id, "name": args.agent_name,
                  "operator": args.operator},
        "issuer": {"id": args.issuer_id, "name": args.issuer_name},
        "iat": now,
        "exp": now + args.ttl,
        "scope": args.scope,
    }
    body["sig"] = keystone.b64u_encode(
        ed25519.sign(keystone.canonical(body), seed))
    out = json.dumps(body, indent=2) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print("wrote %s" % args.out)
    print(out, end="")
    return 0


# ---------------------------------------------------------------- verify

def _resolve_public_key(args, cred):
    if args.public_key:
        return keystone.b64u_decode(args.public_key), "flag"
    keys_url = args.keys_url
    if not keys_url and args.issuer_host:
        keys_url = ("https://%s" % args.issuer_host + WELL_KNOWN % (
            cred["issuer"]["id"], "keys.json"))
    if not keys_url:
        raise ValueError("need --keys-url, --issuer-host, or --public-key")
    doc = _http_get_json(keys_url)
    keys = doc.get("keys") or []
    if not keys:
        raise ValueError("no keys in key document at %s" % keys_url)
    # Draft-01 credentials do not name a key id; the first listed key is
    # the current one.
    return keystone.b64u_decode(keys[0]["public_key"]), keys_url


def _resolve_revocations(args, cred):
    url = args.revocations_url
    if not url and args.issuer_host:
        url = ("https://%s" % args.issuer_host + WELL_KNOWN % (
            cred["issuer"]["id"], "revocations.json"))
    if not url:
        return None, None, "no revocation source given"
    try:
        doc = _http_get_json(url)
    except Exception as exc:
        return None, None, "could not fetch %s (%s)" % (url, exc)
    return doc, url, None


def cmd_verify(args):
    with open(args.credential, encoding="utf-8") as f:
        cred = json.load(f)
    now = time.time()
    checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    ok, agent_echo, issuer_echo = keystone._shape_ok(cred)
    checks = {}
    reason = None
    detail = ""

    if not ok:
        reason = "malformed"
        checks = {"test_credential": False, "signature": False,
                  "not_expired": False, "not_revoked": False}
    else:
        checks["test_credential"] = (cred.get("scope") == "test")

        sig_ok = False
        try:
            pk, key_source = _resolve_public_key(args, cred)
            sig_bytes = keystone.b64u_decode(cred["sig"])
            body = {k: v for k, v in cred.items() if k != "sig"}
            sig_ok = (len(sig_bytes) == 64
                      and ed25519.verify(sig_bytes,
                                         keystone.canonical(body), pk))
        except Exception as exc:
            detail = "key resolution failed: %s" % exc
        checks["signature"] = sig_ok

        checks["not_expired"] = cred["exp"] > now

        # Revocation: fail closed. A missing, unsigned, or stale list
        # means the credential cannot be trusted.
        revoked_ok = False
        doc, url, err = _resolve_revocations(args, cred)
        if err:
            detail = (detail + "; " if detail else "") + err
        elif doc is not None:
            try:
                pk, _src = _resolve_public_key(args, cred)
                rbody = {k: doc[k] for k in
                         ("issuer_id", "key_id", "issued_at", "revoked")}
                list_sig_ok = ed25519.verify(
                    keystone.b64u_decode(doc["sig"]),
                    keystone.canonical(rbody), pk)
                fresh = (now - doc["issued_at"]) < \
                    keystone.REVOCATION_MAX_AGE_S
                if list_sig_ok and fresh:
                    revoked_ids = {r.get("credential_id")
                                   for r in doc["revoked"]
                                   if isinstance(r, dict)}
                    revoked_ok = cred["sig"] not in revoked_ids
                else:
                    detail = (detail + "; " if detail else "") + \
                        ("revocation list signature invalid"
                         if not list_sig_ok else
                         "revocation list older than 24h (stale)")
            except Exception as exc:
                detail = (detail + "; " if detail else "") + \
                    "revocation check failed: %s" % exc
        checks["not_revoked"] = revoked_ok

        order = [("test_credential", "not_test_credential"),
                 ("signature", "invalid_signature"),
                 ("not_expired", "expired"),
                 ("not_revoked", "revoked")]
        reason = next((r for c, r in order if not checks[c]), None)

    verdict = {None: "Valid",
               "not_test_credential": "Not a test credential",
               "invalid_signature": "Invalid signature",
               "expired": "Expired",
               "revoked": "Revoked",
               "malformed": "Malformed"}[reason]
    resp = {"valid": reason is None,
            "checks": checks,
            "issuer": issuer_echo,
            "agent": agent_echo,
            "checked_at": checked_at}
    if reason is not None:
        resp["reason"] = reason
    if detail:
        resp["detail"] = detail
    print(verdict)
    print(json.dumps(resp, indent=2))
    return 0 if reason is None else 1


# ---------------------------------------------------------------- revoke

def cmd_revoke(args):
    keydoc, seed = _load_key(args.key)
    try:
        with open(args.revocations, encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        doc = {"issuer_id": args.issuer_id, "key_id": keydoc["key_id"],
               "issued_at": 0, "revoked": []}
    if doc.get("issuer_id") != args.issuer_id:
        raise ValueError("revocation list is for issuer %r, not %r"
                         % (doc.get("issuer_id"), args.issuer_id))
    now = int(time.time())
    ids = {r.get("credential_id") for r in doc["revoked"]
           if isinstance(r, dict)}
    if args.credential_id not in ids:
        doc["revoked"].append({"credential_id": args.credential_id,
                               "revoked_at": now})
    doc["issued_at"] = now
    doc["key_id"] = keydoc["key_id"]
    body = {k: doc[k] for k in
            ("issuer_id", "key_id", "issued_at", "revoked")}
    doc["sig"] = keystone.b64u_encode(
        ed25519.sign(keystone.canonical(body), seed))
    with open(args.revocations, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("revoked %s... (%d total on the list)"
          % (args.credential_id[:16], len(doc["revoked"])))
    print("wrote %s — publish it where your key document says it lives."
          % args.revocations)
    return 0


# ------------------------------------------------------------------ main

def main(argv=None):
    p = argparse.ArgumentParser(
        prog="keystone-issuer.py",
        description="Keystone issuer toolkit (spec draft-01). Stdlib only.")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    g.add_argument("--out", default="issuer-private.json",
                   help="private key file to write (mode 600)")
    g.add_argument("--key-id", default=None,
                   help="key id (default kid-YYYYMMDD)")
    g.set_defaults(func=cmd_keygen)

    g = sub.add_parser("keydoc", help="emit the well-known key document")
    g.add_argument("--key", required=True, help="private key file")
    g.add_argument("--issuer-id", required=True)
    g.add_argument("--issuer-name", required=True)
    g.add_argument("--host", default=DEFAULT_HOST,
                   help="host serving the well-known path "
                        "(default: the test verifier host)")
    g.add_argument("--revocations-url", default=None,
                   help="override the revocations URL in the document")
    g.add_argument("--out", default=None, help="write to file instead "
                   "of stdout")
    g.set_defaults(func=cmd_keydoc)

    g = sub.add_parser("sign", help="sign a credential for an agent")
    g.add_argument("--key", required=True, help="private key file")
    g.add_argument("--issuer-id", required=True)
    g.add_argument("--issuer-name", required=True)
    g.add_argument("--agent-id", required=True)
    g.add_argument("--agent-name", required=True)
    g.add_argument("--operator", required=True)
    g.add_argument("--ttl", type=int, default=86400,
                   help="seconds until expiry (default 86400)")
    g.add_argument("--scope", default="test")
    g.add_argument("--out", default=None)
    g.set_defaults(func=cmd_sign)

    g = sub.add_parser("verify", help="verify a credential locally")
    g.add_argument("credential", help="credential JSON file")
    g.add_argument("--keys-url", default=None,
                   help="issuer key document URL")
    g.add_argument("--issuer-host", default=None,
                   help="derive well-known URLs from this host")
    g.add_argument("--public-key", default=None,
                   help="base64url public key (skips key discovery)")
    g.add_argument("--revocations-url", default=None)
    g.set_defaults(func=cmd_verify)

    g = sub.add_parser("revoke", help="revoke a credential and re-sign "
                       "the revocation list")
    g.add_argument("--key", required=True, help="private key file")
    g.add_argument("--issuer-id", required=True)
    g.add_argument("--revocations", required=True,
                   help="revocation list file (created if missing)")
    g.add_argument("--credential-id", required=True,
                   help="the credential's sig value")
    g.set_defaults(func=cmd_revoke)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
