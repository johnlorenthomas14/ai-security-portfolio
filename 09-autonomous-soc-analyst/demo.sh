#!/usr/bin/env bash
# 60-90 second walkthrough of the Autonomous SOC Analyst Agent.
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
echo "  Autonomous SOC Analyst Agent — Project 9"
echo "  (tool-use loop · input-guarded by Project 1 · 6 analyst tools)"
echo
sleep 1.5

type_cmd 'cat README.md | head -8'
sleep 1

echo "→ shipped demo notables"
type_cmd 'cat samples/notables.jsonl'

echo "→ run the agent over the demo notables"
type_cmd 'python3 analyst.py'

echo "→ first triage report (Markdown)"
type_cmd 'ls out/reports/'

echo "→ run the eval suite against golden triage outcomes"
type_cmd 'python3 analyst.py --eval'

echo "→ pytest"
type_cmd 'python3 -m pytest -q'

echo
echo "  Six tools, one input guard, one tool-use loop. The agent's own"
echo "  input layer is defended by the portfolio's runtime detector"
echo "  (Project 1) — closing the loop on AI-security-as-defense-in-depth."
echo "  Eval suite scores agent vs. golden triage outcomes; CI enforces"
echo "  a pass-rate floor."
