#!/usr/bin/env bash
# 60-90 second walkthrough of the SIEM Correlation Rule Generator.
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
echo "  SIEM Correlation Rule Generator — demo"
echo "  (canonical YAML → Splunk ES + Sigma + Cortex XSIAM)"
echo
sleep 1.5

type_cmd 'cat README.md | head -8'
sleep 1

echo "→ canonical rule library: 8 YAML rules covering Projects 1, 2, 3 events"
type_cmd 'ls templates/'

echo "→ one canonical rule (AIPI-003 — tool-abuse attempt; critical severity)"
type_cmd 'cat templates/AIPI-003-tool-abuse-attempt.yaml'

echo "→ run the generator over the whole library"
type_cmd 'python3 generator.py'

echo "→ Splunk ES correlation search emitted from AIPI-003"
type_cmd 'cat out/splunk_es/AIPI-003.conf'

echo "→ Sigma rule emitted from the same canonical YAML"
type_cmd 'cat out/sigma/AIPI-003.yml'

echo "→ Cortex XSIAM XQL emitted from the same canonical YAML"
type_cmd 'cat out/cortex_xsiam/AIPI-003.xql'

echo "→ coverage map (OWASP / AI RMF rollups)"
type_cmd 'head -30 out/coverage_map.md'

echo "→ pytest suite (offline, no API key)"
type_cmd 'python3 -m pytest -q'

echo
echo "  One canonical rule → three SIEM outputs. Detection content authored"
echo "  once is portable across Splunk ES, any Sigma-compatible SIEM, and"
echo "  Cortex XSIAM — exactly the dual-stack content shape modern AI"
echo "  security programs need."
