#!/usr/bin/env bash
# Picks a random prime minute (primes in 0-59) and writes it into the cron
# line of .github/workflows/message-me-cve.yml. Runs are hourly; the program
# itself skips NVD when it was polled under 2 h ago.
# Commit the workflow afterwards.
set -euo pipefail
cd "$(dirname "$0")"
wf=.github/workflows/message-me-cve.yml
primes=(2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59)
m=$(shuf -n 1 -e "${primes[@]}")
grep -qE "^    - cron: '[0-9]+ 12-22 \* \* \*'$" "$wf" ||
	{ echo "cron line not found in $wf" >&2; exit 1; }
sed -i -E "s/^(    - cron: ')[0-9]+( 12-22 \* \* \*')$/\1$m\2/" "$wf"
grep -n "cron:" "$wf"
