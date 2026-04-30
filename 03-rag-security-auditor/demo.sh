#!/usr/bin/env bash
# 60-90 second walkthrough of the RAG Pipeline Security Auditor.
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
echo "  RAG Pipeline Security Auditor — demo"
echo "  (corpus-ingestion gate · OWASP LLM02/07 + NIST AI RMF · uses Project 1 detector)"
echo
sleep 1.5

type_cmd 'cat README.md | head -8'
sleep 1

echo "→ demo corpus: 6 documents, several intentionally polluted"
type_cmd 'ls corpus/demo/'

echo "→ a poisoned FAQ (indirect-injection payload embedded in normal-looking text)"
type_cmd 'cat corpus/demo/02-poisoned-faq.md'

echo "→ run the auditor over the corpus"
type_cmd 'python3 auditor.py --corpus corpus/demo'

echo "→ first 30 lines of the Markdown audit report"
type_cmd 'head -30 out/audit_report.md'

echo "→ first 25 lines of findings.json (Splunk-ingestible CIM events)"
type_cmd 'head -25 out/findings.json'

echo "→ pytest suite (offline, no API key)"
type_cmd 'python3 -m pytest -q'

echo
echo "  Findings emit as cim_eventtype=ai_rag_finding events ready for"
echo "  Splunk HEC ingestion. The audit doubles as NIST AI RMF GOVERN"
echo "  and MEASURE evidence — corpus-ingestion control as continuous"
echo "  monitoring."
