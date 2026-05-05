"""IOCEnrichmentTool — mock geo + reputation + ASN lookup for an IOC.

Production deployment would call out to threat-intel platforms
(VirusTotal, GreyNoise, AlienVault OTX, etc.). This MVP returns
deterministic, synthetic enrichment derived from the IOC's structure
so the agent loop can be exercised end-to-end without external network
calls.

Recognized IOC types: ipv4, domain, sha256, url. The tool's heuristics:

  - Private RFC1918 IPs → low reputation 0 (informational, not bad).
  - 203.0.113.x (TEST-NET-3) IPs → reputation 90 (treated as known-bad
    so test notables can route through the malicious-IP code path).
  - Domains matching `*-attacker.example.com` → reputation 95.
  - Other → reputation 30 (unknown / benign-by-default).
"""

from __future__ import annotations

import re
from typing import Any


class IOCEnrichmentTool:
    name = "ioc_enrichment"
    description = (
        "Enrich an indicator of compromise (IPv4, domain, SHA256, URL) "
        "with reputation, geo, and ASN metadata. Use to assess whether a "
        "src_ip or destination domain associated with a notable is a "
        "known-bad actor."
    )
    parameters = {
        "type": "object",
        "properties": {
            "indicator": {
                "type": "string",
                "description": "The IOC value — e.g. '203.0.113.42' or 'attacker.example.com'.",
            },
            "indicator_type": {
                "type": "string",
                "enum": ["ipv4", "domain", "sha256", "url", "auto"],
                "description": "IOC type. Use 'auto' to let the tool detect.",
            },
        },
        "required": ["indicator"],
    }

    def invoke(self, arguments: dict[str, Any]) -> dict[str, Any]:
        ind = str(arguments.get("indicator", "")).strip()
        kind = str(arguments.get("indicator_type", "auto")).lower()
        if kind == "auto" or not kind:
            kind = self._detect_type(ind)

        if kind == "ipv4":
            return self._enrich_ip(ind)
        if kind == "domain":
            return self._enrich_domain(ind)
        if kind == "sha256":
            return self._enrich_hash(ind)
        if kind == "url":
            return self._enrich_url(ind)
        return {
            "indicator": ind,
            "indicator_type": kind,
            "reputation": 0,
            "verdict": "unknown",
            "rationale": "Indicator type not recognized.",
        }

    # ------------------------------------------------------------------

    def _detect_type(self, value: str) -> str:
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
            return "ipv4"
        if re.fullmatch(r"[a-fA-F0-9]{64}", value):
            return "sha256"
        if value.startswith(("http://", "https://")):
            return "url"
        if "." in value and re.fullmatch(r"[A-Za-z0-9.-]+", value):
            return "domain"
        return "unknown"

    def _enrich_ip(self, ip: str) -> dict[str, Any]:
        # RFC1918 — internal, not interesting from a reputation standpoint.
        if ip.startswith(("10.", "192.168.")) or _is_172_16_to_31(ip):
            return {
                "indicator": ip, "indicator_type": "ipv4",
                "reputation": 0, "verdict": "internal",
                "rationale": "RFC1918 private address — internal asset, no reputation.",
                "asn": "PRIVATE", "country": "N/A",
            }
        # TEST-NET-3 — treated as known-malicious so the eval set has a
        # deterministic "bad IP" path.
        if ip.startswith("203.0.113."):
            return {
                "indicator": ip, "indicator_type": "ipv4",
                "reputation": 90, "verdict": "malicious",
                "rationale": (
                    "Source IP appears in three threat-intel feeds across the "
                    "last 7 days. Associated with credential-harvesting "
                    "infrastructure."
                ),
                "asn": "AS65500 (synthetic)", "country": "ZZ",
            }
        # Other public IPs — informational.
        return {
            "indicator": ip, "indicator_type": "ipv4",
            "reputation": 30, "verdict": "unknown",
            "rationale": "No matching threat-intel records.",
            "asn": "AS-UNKNOWN", "country": "ZZ",
        }

    def _enrich_domain(self, domain: str) -> dict[str, Any]:
        d = domain.lower()
        if d.endswith("attacker.example.com") or "attacker" in d:
            return {
                "indicator": domain, "indicator_type": "domain",
                "reputation": 95, "verdict": "malicious",
                "rationale": (
                    "Domain matches the known-bad attacker.example.com "
                    "infrastructure pattern. Listed in an internal blocklist "
                    "feed since 2026-02-08."
                ),
                "registrar": "Synthetic Registrar Inc.",
                "first_seen": "2026-02-08",
            }
        if d.endswith("acme-sso.example-attacker.com"):
            return {
                "indicator": domain, "indicator_type": "domain",
                "reputation": 92, "verdict": "malicious",
                "rationale": "Look-alike domain mimicking ACME SSO portal.",
                "registrar": "Synthetic Registrar Inc.",
                "first_seen": "2026-02-08",
            }
        return {
            "indicator": domain, "indicator_type": "domain",
            "reputation": 20, "verdict": "benign",
            "rationale": "Domain has no negative reputation records.",
        }

    def _enrich_hash(self, sha256: str) -> dict[str, Any]:
        # The known-bad hash from Project 7's phishing-campaign bundle.
        if sha256.startswith("a1b2c3d4e5f607"):
            return {
                "indicator": sha256, "indicator_type": "sha256",
                "reputation": 95, "verdict": "malicious",
                "rationale": (
                    "Hash matches the FinSector phishing landing-page artifact "
                    "(see threat-intel bundle bundle--01-phishing-campaign-2026q1)."
                ),
                "first_seen": "2026-02-08",
            }
        return {
            "indicator": sha256, "indicator_type": "sha256",
            "reputation": 25, "verdict": "unknown",
            "rationale": "Hash not present in threat-intel feeds.",
        }

    def _enrich_url(self, url: str) -> dict[str, Any]:
        if "attacker" in url.lower():
            return {
                "indicator": url, "indicator_type": "url",
                "reputation": 95, "verdict": "malicious",
                "rationale": "URL hosted on known-bad attacker.example.com infrastructure.",
            }
        return {
            "indicator": url, "indicator_type": "url",
            "reputation": 25, "verdict": "unknown",
            "rationale": "URL not present in threat-intel feeds.",
        }


def _is_172_16_to_31(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4 or parts[0] != "172":
        return False
    try:
        return 16 <= int(parts[1]) <= 31
    except ValueError:
        return False
