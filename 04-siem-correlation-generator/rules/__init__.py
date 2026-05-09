"""Rule schema and generator protocol.

A canonical Rule object loaded from a single YAML file is consumed by
every generator. Each generator produces detection content in its
SIEM's native format from the same canonical input.
"""

from .base import Aggregation, Condition, Rule, Response, RuleGenerator, load_rule, load_rules
from .splunk_es import SplunkESGenerator
from .sigma import SigmaGenerator
from .cortex_xsiam import CortexXSIAMGenerator
from .morpheus import MorpheusGenerator

__all__ = [
    "Aggregation",
    "Condition",
    "Rule",
    "Response",
    "RuleGenerator",
    "load_rule",
    "load_rules",
    "SplunkESGenerator",
    "SigmaGenerator",
    "CortexXSIAMGenerator",
    "MorpheusGenerator",
]
