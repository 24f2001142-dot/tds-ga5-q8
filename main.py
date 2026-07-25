import ipaddress
import os
import socket
from typing import Any, Dict
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-2da970bcb1"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
MAX_REDIRECTS = 5


class ToolCall(BaseModel):
    tool: str
    arguments: Dict[str, Any]


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------

def safe_read_file(path: str):
    if not isinstance(path, str) or path == "":
        return "block", "Path must be a non-empty string.", None

    # Build the candidate path. Do NOT url-decode - treat the string literally,
    # exactly as JSON gave it to us.
    if os.path.isabs(path):
        candidate = path
    else:
        candidate = os.path.join(SANDBOX_ROOT, path)

    # Resolve symlinks / normalize .. and . segments to get the *real* target.
    real_root = os.path.realpath(SANDBOX_ROOT)
    real_candidate = os.path.realpath(candidate)

    # Boundary check: real_candidate must be == real_root or a proper
    # descendant of real_root (root + os.sep prefix), never merely a string
    # startswith match without the separator (that would wrongly allow
    # a sibling dir like sandbox-2da970bcb1-evil).
    if real_candidate != real_root and not real_candidate.startswith(real_root + os.sep):
        return "block", "Path resolves outside the allowed sandbox directory.", None

    if not os.path.isfile(real_candidate):
        return "block", "File does not exist inside the sandbox.", None

    try:
        with open(real_candidate, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return "block", f"Could not read file: {e}", None

    return "allow", "Path is inside the sandbox.", content


# ---------------------------------------------------------------------------
# fetch_url
# ---------------------------------------------------------------------------

def host_is_disallowed_ip(host: str) -> bool:
    """Resolve host to IP(s) and check if any resolved address is
    private/loopback/link-local/reserved/multicast (covers SSRF to
    metadata endpoints, internal networks, etc.)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return True  # can't resolve -> treat as unsafe/block

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True
    return False


def check_url_allowed(url: str):
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Could not parse URL."

    if parsed.scheme not in ("http", "https"):
        return False, "Only http/https URLs are allowed."

    # urlparse.hostname correctly strips userinfo (user:pass@host) and port,
    # so a URL like http://example.com@evil.com/ correctly yields
    # hostname == 'evil.com', not 'example.com'.
    host = (parsed.hostname or "").lower()

    if host not in ALLOWED_HOSTS:
        return False, f"Host '{host}' is not on the exact allowlist."

    if host_is_disallowed_ip(host):
        return False, "Host resolves to a private/internal/reserved IP address."

    return True, "Host is allowed and resolves to a public address."


def safe_fetch_url(url: str):
    if not isinstance(url, str) or url == "":
        return "block", "URL must be a non-empty string.", None

    ok, reason = check_url_allowed(url)
    if not ok:
        return "block", reason, None

    current_url = url
    redirects = 0

    try:
        with httpx.Client(follow_redirects=False, timeout=6.0) as client:
            while True:
                resp = client.get(current_url)

                if resp.status_code in (301, 302, 303, 307, 308):
                    redirects += 1
                    if redirects > MAX_REDIRECTS:
                        return "block", "Too many redirects.", None
                    location = resp.headers.get("location")
                    if not location:
                        return "block", "Redirect with no Location header.", None
                    # Resolve relative redirects against current_url
                    from urllib.parse import urljoin
                    next_url = urljoin(current_url, location)
                    ok, reason = check_url_allowed(next_url)
                    if not ok:
                        return "block", f"Redirect target disallowed: {reason}", None
                    current_url = next_url
                    continue

                text = resp.text
                return "allow", "Fetched successfully from an allowed host.", text
    except Exception as e:
        return "block", f"Fetch failed: {e}", None


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.post("/guardrail")
def guardrail(call: ToolCall):
    if call.tool == "read_file":
        path = call.arguments.get("path")
        action, reason, result = safe_read_file(path)
    elif call.tool == "fetch_url":
        url = call.arguments.get("url")
        action, reason, result = safe_fetch_url(url)
    else:
        action, reason, result = "block", "Unknown tool.", None

    response = {"action": action, "reason": reason}
    if action == "allow":
        response["result"] = result
    return response


@app.get("/")
def root():
    return {"status": "ok"}
