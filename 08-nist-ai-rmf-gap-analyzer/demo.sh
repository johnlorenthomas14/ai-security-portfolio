#!/usr/bin/env bash
# 60-90 second walkthrough of the NIST AI RMF Compliance Gap Analyzer.
# Designed for asciinema:
#   asciinema rec -c "./demo.sh" demo.cast
set -e

type_cmd() {
    local cmd="$1"
    printf "$ "
    for ((i=0; i<${#cmd}; i++)); do
        printf "${cmd:$i:1}"
        sleep 0.025
    done
    printf "\n"
    eval "$cmd" || true
    printf "\n"
    sleep 1
}

clear
echo "  NIST AI RMF Compliance Gap Analyzer — capstone demo"
echo "  (aggregates Projects 1-7 outputs into a continuous-monitoring evidence report)"
echo
sleep 1.5

type_cmd 'cat README.md | head -10'
sleep 1

echo "→ AI RMF catalog (representative subset of NIST AI 100-1)"
type_cmd 'python3 -c "from rmf import CATALOG; from rmf.catalog import Function; print(f\"Catalogued {len(CATALOG)} subcategories across {len({s.function for s in CATALOG})} functions\"); [print(f\"  {fn.value:<8} — {sum(1 for s in CATALOG if s.function == fn)} subcategories\") for fn in Function]"'

echo "→ run the analyzer over the portfolio"
type_cmd 'python3 analyzer.py'

echo "→ first 30 lines of the gap report"
type_cmd 'head -30 out/gap_report.md'

echo "→ top covered subcategories with evidence references"
type_cmd "python3 -c 'import json; d=json.load(open(\"out/coverage.json\")); [print(\"  {} ({}): {} item(s) from {}\".format(s[\"id\"], s[\"function\"], s[\"n_evidence_items\"], s[\"contributing_projects\"])) for s in d[\"subcategories\"] if s[\"covered\"]][:8]'"

echo "→ pytest suite"
type_cmd 'python3 -m pytest -q'

echo
echo "  The portfolio's eight projects share an event vocabulary, a"
echo "  taxonomy (OWASP / ATLAS / AI RMF), and a Splunk pipeline. Project 8"
echo "  reads what the other seven produce, maps each finding to its"
echo "  AI RMF subcategory, and produces continuous-monitoring evidence —"
echo "  the same Q-Compliance / Q-Audit pattern, applied to AI governance."
