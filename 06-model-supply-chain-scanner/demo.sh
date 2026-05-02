#!/usr/bin/env bash
# 60-90 second walkthrough of the AI Model Supply Chain Risk Scanner.
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
echo "  AI Model Supply Chain Risk Scanner — demo"
echo "  (pickle opcode analysis · provenance · deps · CycloneDX SBOM)"
echo
sleep 1.5

type_cmd 'cat README.md | head -8'
sleep 1

echo "→ demo model directory structure"
type_cmd 'ls samples/demo_model/'

echo "→ run the scanner over the demo model"
type_cmd 'python3 scanner.py --model samples/demo_model'

echo "→ first 30 lines of the Markdown audit report"
type_cmd 'head -30 out/audit_report.md'

echo "→ generated CycloneDX 1.5 SBOM fragment (first 25 lines)"
type_cmd 'head -25 out/sbom.cdx.json'

echo "→ pytest suite — covers each scanner, plus a programmatically-built malicious pickle"
type_cmd 'python3 -m pytest -q'

echo
echo "  The pickle scanner uses Python's pickletools to disassemble weight"
echo "  files WITHOUT executing them. Any GLOBAL opcode referencing a"
echo "  non-allowlisted module (os, subprocess, socket, requests, ...) is"
echo "  flagged. The CycloneDX SBOM fragment integrates with Anchore /"
echo "  Snyk / Trivy / Dependabot for downstream supply-chain tooling."
