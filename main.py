import ipaddress
import os
import socket
from typing import Any, Dict, Optional
from urllib.parse import urlparse, urljoin

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

    if os.path.isabs(path):
        candidate = path
    else:
        candidate = os.path.join(SANDBOX_ROOT, path)

    real_root = os.path.realpath(SANDBOX_ROOT)
    real_candidate = os.path.realpath(candidate)

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

def normalize_host(host: str) -> str:
    host = host.lower().strip()
    if host.endswith("."):
        host = host[:-1]
    return host


def resolve_public_ip(host: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return None

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            continue
        return ip_str
    return None


def validate_and_pin(url: str):
    """Returns (ok, reason, host, pinned_ip, scheme, port) for a URL.
    Any parsing failure anywhere in this function results in a block,
    never an unhandled exception."""
    try:
        parsed = urlparse(url)

        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return False, "Only http/https URLs are allowed.", None, None, None, None

        if parsed.username or parsed.password:
            return False, "URLs with embedded userinfo are not allowed.", None, None, None, None

        raw_host = parsed.hostname
        if not raw_host:
            return False, "URL has no valid host.", None, None, None, None

        host = normalize_host(raw_host)

        if host not in ALLOWED_HOSTS:
            return False, f"Host '{host}' is not on the exact allowlist.", None, None, None, None

        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80

        pinned_ip = resolve_public_ip(host)
        if pinned_ip is None:
            return False, "Host does not resolve to any public IP address.", None, None, None, None

        return True, "Host is allowed and resolves to a public address.", host, pinned_ip, scheme, port

    except Exception as e:
        return False, f"URL could not be safely parsed: {e}", None, None, None, None


def safe_fetch_url(url: str):
    if not isinstance(url, str) or url == "":
        return "block", "URL must be a non-empty string.", None

    current_url = url
    redirects = 0

    while True:
        ok, reason, host, pinned_ip, scheme, port = validate_and_pin(current_url)
        if not ok:
            return "block", reason, None

        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=6.0,
                headers={"Host": host},
            ) as client:
                parsed = urlparse(current_url)
                path_and_query = parsed.path or "/"
                if parsed.query:
                    path_and_query += "?" + parsed.query

                pinned_url = f"{scheme}://{pinned_ip}:{port}{path_and_query}"

                if scheme == "https":
                    resp = client.get(
                        pinned_url,
                        extensions={"sni_hostname": host},
                    )
                else:
                    resp = client.get(pinned_url)

        except Exception as e:
            return "block", f"Fetch failed: {e}", None

        if resp.status_code in (301, 302, 303, 307, 308):
            redirects += 1
            if redirects > MAX_REDIRECTS:
                return "block", "Too many redirects.", None
            location = resp.headers.get("location")
            if not location:
                return "block", "Redirect with no Location header.", None
            current_url = urljoin(current_url, location)
            continue

        return "allow", "Fetched successfully from an allowed, pinned host.", resp.text


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
