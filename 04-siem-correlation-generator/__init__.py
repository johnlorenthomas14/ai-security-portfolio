"""SIEM Correlation Rule Generator for AI Workloads.

Consumes the JSON event shapes Projects 1, 2, and 3 emit. Produces
correlation content across three SIEM platforms (Splunk ES, Sigma,
Cortex XSIAM) from a single canonical YAML rule definition per detection.
"""
