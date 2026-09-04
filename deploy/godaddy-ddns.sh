#!/usr/bin/env bash
# Keeps rgcdoortodoorboxservices.ca pointed at this machine's current public
# IP. Only needed if your home internet connection does NOT have a static
# IP (most residential connections don't) — run this on a cron job every
# 5-15 minutes. If your ISP gives you a static IP, skip this script entirely
# and just set the A record once in GoDaddy's DNS manager.
#
# Requires a GoDaddy API key/secret (Production, not OTE/test):
# https://developer.godaddy.com/keys
set -euo pipefail

GODADDY_API_KEY="__REPLACE_ME__"
GODADDY_API_SECRET="__REPLACE_ME__"
DOMAIN="rgcdoortodoorboxservices.ca"
RECORD_NAMES=("@" "www")   # "@" = the bare domain; keep "www" too if you use it
TTL=600

CURRENT_IP="$(curl -s https://api.ipify.org)"
if [[ -z "$CURRENT_IP" ]]; then
    echo "$(date -Is) Could not determine public IP, skipping." >&2
    exit 1
fi

for RECORD_NAME in "${RECORD_NAMES[@]}"; do
    DNS_IP="$(curl -s \
        -H "Authorization: sso-key ${GODADDY_API_KEY}:${GODADDY_API_SECRET}" \
        "https://api.godaddy.com/v1/domains/${DOMAIN}/records/A/${RECORD_NAME}" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['data'] if d else '')" 2>/dev/null || echo "")

    if [[ "$CURRENT_IP" == "$DNS_IP" ]]; then
        continue  # already up to date
    fi

    curl -s -X PUT \
        -H "Authorization: sso-key ${GODADDY_API_KEY}:${GODADDY_API_SECRET}" \
        -H "Content-Type: application/json" \
        -d "[{\"data\": \"${CURRENT_IP}\", \"ttl\": ${TTL}}]" \
        "https://api.godaddy.com/v1/domains/${DOMAIN}/records/A/${RECORD_NAME}" > /dev/null

    echo "$(date -Is) Updated ${RECORD_NAME}.${DOMAIN}: ${DNS_IP:-<none>} -> ${CURRENT_IP}"
done
