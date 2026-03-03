#!/bin/bash
# Record coercex demo for README
# Uses test-targets.txt with short timeout since targets may be unreachable
set -e

cd /home/nonsleepr/code/coercex

echo "coercex -- Async NTLM Authentication Coercion Scanner"
echo "======================================================"
echo ""
echo "$ coercex scan -T test-targets.txt -u user -p pass --smb-port 4445 --http-port 8080 --timeout 2"
echo ""

uv run coercex scan -T test-targets.txt -u user -p 'pass' \
  --smb-port 4445 --http-port 8080 \
  --timeout 2 -c 20

echo ""
echo "Scan complete."
