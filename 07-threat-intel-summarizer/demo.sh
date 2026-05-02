#!/usr/bin/env bash
# 60-90 second walkthrough of the Threat Intelligence Summarizer.
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
echo "  Threat Intelligence Summarizer — demo"
echo "  (STIX 2.1 → cited analyst brief → Splunk notables · citation-verified)"
echo
sleep 1.5

type_cmd 'cat README.md | head -8'
sleep 1

echo "→ shipped STIX bundles"
type_cmd 'ls samples/stix_bundles/'

echo "→ a STIX bundle's object types"
type_cmd 'python3 -c "import json,sys; b=json.load(open(\"samples/stix_bundles/01-phishing-campaign.json\")); print(\"\\n\".join(sorted(set(o[\"type\"] for o in b[\"objects\"]))))"'

echo "→ run the summarizer offline (uses the stub client; CI-friendly)"
type_cmd 'python3 summarizer.py --offline'

echo "→ first 30 lines of the generated phishing-campaign brief"
type_cmd 'head -30 out/briefs/01-phishing-campaign.md'

echo "→ first 25 lines of the emitted Splunk notables"
type_cmd 'head -25 out/notables/01-phishing-campaign.json'

echo "→ citation audit (zero hallucinations expected from stub)"
type_cmd 'cat out/citation_audit.json'

echo "→ pytest suite"
type_cmd 'python3 -m pytest -q'

echo
echo "  Every claim in the brief is bound to a STIX object ID. The verifier"
echo "  walks the markdown, extracts every [type--uuid] reference, and"
echo "  rejects any citation that doesn't resolve to a real bundle object."
echo "  That's the discipline a SOC needs before it can rely on LLM-"
echo "  generated intel briefs."
