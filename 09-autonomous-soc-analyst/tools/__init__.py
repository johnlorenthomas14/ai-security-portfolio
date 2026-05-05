"""Analyst tools — six callable tools the agent can invoke during triage.

Each tool implements the Tool protocol: name, description, parameters,
and a callable that takes the parsed parameters and returns a
ToolResult dict. The deterministic, mock-backed implementations make
the agent runnable end-to-end without external services (no live
Splunk, no live STIX TAXII, no real WHOIS).
"""

from .base import Tool, ToolCall, ToolResult, registry
from .splunk_search import SplunkSearchTool
from .ioc_enrichment import IOCEnrichmentTool
from .atlas_lookup import AtlasLookupTool
from .stix_lookup import StixLookupTool
from .escalate import EscalateToHumanTool
from .summarize import SummarizeTool


def default_tools(portfolio_root=None):
    """Return the six default tools wired to their backing data sources."""
    return [
        SplunkSearchTool(),
        IOCEnrichmentTool(),
        AtlasLookupTool(),
        StixLookupTool(portfolio_root=portfolio_root),
        EscalateToHumanTool(),
        SummarizeTool(),
    ]


__all__ = [
    "Tool",
    "ToolCall",
    "ToolResult",
    "registry",
    "default_tools",
    "SplunkSearchTool",
    "IOCEnrichmentTool",
    "AtlasLookupTool",
    "StixLookupTool",
    "EscalateToHumanTool",
    "SummarizeTool",
]
