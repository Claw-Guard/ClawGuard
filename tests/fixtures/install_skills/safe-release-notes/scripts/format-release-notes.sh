#!/usr/bin/env bash
set -euo pipefail

# Convert non-empty standard-input lines into a local Markdown checklist.
awk 'NF > 0 { sub(/^[[:space:]]+/, ""); print "- [ ] " $0 }'
