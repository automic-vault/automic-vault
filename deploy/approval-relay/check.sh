#!/bin/sh
set -eu

# Verify public TLS and routing to the relay, whose health endpoint returns 204.
status=$(curl --silent --show-error --connect-timeout 5 --max-time 15 \
    --output /dev/null --write-out '%{http_code}' \
    https://approval-relay.automicvault.com/health)
test "$status" = 204
