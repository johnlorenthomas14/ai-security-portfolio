"""NIST AI RMF Compliance Gap Analyzer — the portfolio capstone.

Reads outputs from Projects 1-7, maps each finding to a NIST AI RMF 1.0
subcategory (using the airmf_subcategory tag every project emits),
computes per-subcategory and per-function coverage, and produces a gap
report identifying which AI RMF controls have measurable evidence and
which remain uncovered.

Maps directly to the Qmulos Q-Compliance / Q-Audit pattern — continuous-
compliance evidence collection — extended into AI governance instead of
NIST 800-53.
"""
