"""Best-effort Splunk HEC forwarder.

Reads SPLUNK_HEC_URL / SPLUNK_HEC_TOKEN / SPLUNK_HEC_INDEX from env.
If any are missing it becomes a no-op, so dev environments still work.

Intentionally uses urllib only — no extra deps for the MVP.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("aisec.prompt_injection.hec")


def _bool_env(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}


def forward_to_splunk(event: dict[str, Any], *, sourcetype: str = "aisec:prompt_injection") -> bool:
    """Forward a single detection event to Splunk HEC. Returns True on success."""
    url = os.environ.get("SPLUNK_HEC_URL")
    token = os.environ.get("SPLUNK_HEC_TOKEN")
    if not url or not token:
        logger.debug("Splunk HEC not configured; skipping forward.")
        return False

    payload = {
        "event": event,
        "sourcetype": sourcetype,
        "index": os.environ.get("SPLUNK_HEC_INDEX", "aisec"),
    }
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
    )

    verify_tls = _bool_env("SPLUNK_HEC_VERIFY_TLS", True)
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            if 200 <= resp.status < 300:
                return True
            logger.warning("Splunk HEC non-2xx: %s", resp.status)
            return False
    except (urllib.error.URLError, TimeoutError) as exc:
        logger.warning("Splunk HEC forward failed: %s", exc)
        return False
