#!/usr/bin/env bash
# 60-90 second walkthrough of the AI Red-Team Automation Framework.
# Designed for asciinema:
#   asciinema rec -c "./demo.sh" demo.cast
set -e

# slow-type effect for the recording
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
echo "  AI Red-Team Automation Framework — demo"
echo "  (OWASP LLM Top 10 + NIST AI RMF; uses Project 1 as input-side scorer)"
echo
sleep 1.5

type_cmd 'cat README.md | head -8'
sleep 1

echo "→ probe library: 20 YAML attacks across 5 OWASP LLM Top 10 categories"
type_cmd 'ls attack-library/'

echo "→ a single probe (direct prompt injection — PROBE-LLM01-001)"
type_cmd 'head -22 attack-library/llm01_prompt_injection.yaml'

echo "→ run the framework against the deliberately-vulnerable demo target"
type_cmd 'python3 runner.py --target demo'

echo "→ first 30 lines of the AI RMF Markdown evidence report"
type_cmd 'head -30 out/airmf_evidence.md'

echo "→ first 25 lines of findings.json (Splunk-ingestible CIM events)"
type_cmd 'head -25 out/findings.json'

echo "→ pytest suite (offline, no API key)"
type_cmd 'python3 -m pytest -q'

echo
echo "  Each finding emits a CIM-shaped JSON event ready to forward to"
echo "  Splunk Enterprise Security via HEC. The Markdown report doubles"
echo "  as NIST AI RMF Manage-function input — runtime probing as"
echo "  continuous-monitoring evidence."
