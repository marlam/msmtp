#!/usr/bin/env bash

set -e

# Start an msmtpd with PLAIN authentication
echo "Starting msmtpd"
../src/msmtpd --interface=::1 --port=12345 --auth='testuser,echo testpassword' \
	--command='cat > out-auth-plain-mail.txt; echo > out-auth-plain-rcpt.txt' &
MSMTPD_PID=$!
trap "kill $MSMTPD_PID" EXIT

# Input mail example
echo "Generating test mail"
cat > mail-auth-plain.txt << EOF
Subject: Test

This is a test.
EOF

# Check if msmtp can authenticate
echo "Testing auth PLAIN"
../src/msmtp --host=::1 --port=12345 --auth=plain --user=testuser --passwordeval="echo testpassword" \
	--from test@example.com recipient@example.com < mail-auth-plain.txt
