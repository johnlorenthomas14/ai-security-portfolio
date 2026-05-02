#!/usr/bin/env bash
# 60-90 second walkthrough of the LLM Output Compliance Monitor.
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
echo "  LLM Output Safety & Compliance Monitor — demo"
echo "  (4 output filters · hash-chained audit log · FedRAMP-flavored)"
echo
sleep 1.5

type_cmd 'cat README.md | head -8'
sleep 1

echo "→ shipped corpus: 8 clean LLM outputs, 11 deliberately bad ones"
type_cmd 'wc -l samples/good_outputs.jsonl samples/bad_outputs.jsonl'

echo "→ a single bad response (BAD-SEC-002 — Anthropic API key in output)"
type_cmd 'head -5 samples/bad_outputs.jsonl | tail -1'

echo "→ replay the bad-output corpus through the monitor"
type_cmd 'python3 monitor.py --corpus samples/bad_outputs.jsonl --audit-log out/audit.jsonl'

echo "→ replay the good-output corpus too — every response must pass"
type_cmd 'python3 monitor.py --corpus samples/good_outputs.jsonl --audit-log out/audit.jsonl'

echo "→ verify the audit log's hash chain"
type_cmd 'python3 monitor.py --verify out/audit.jsonl'

echo "→ first 3 audit entries (prev_hash chains them together)"
type_cmd 'head -3 out/audit.jsonl | python3 -m json.tool --json-lines | head -50'

echo "→ pytest suite (offline, no API key)"
type_cmd 'python3 -m pytest -q'

echo
echo "  Every monitor decision is appended to a hash-chained log. Each entry's"
echo "  prev_hash binds to the previous entry's hash — tampering with any past"
echo "  entry breaks the chain and verify_chain() detects it. That's the"
echo "  FedRAMP-flavored integrity-evidence pattern this project is shaped"
echo "  around."
