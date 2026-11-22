#!/usr/bin/env bash

set -e

msmtpd=../src/msmtpd
if [ ! -x $msmtpd ]; then
	echo 'msmtpd is not built'
	exit 77
fi

# Start an msmtpd that dumps the recipient list so we can check it
echo "Starting msmtpd"
$msmtpd --interface=::1 --port=12347 \
	--command='cat > /dev/null; echo > out-aliases-rcpt.txt' &
MSMTPD_PID=$!
trap "kill $MSMTPD_PID" EXIT

echo "Generating aliases file and test mail"
cat > aliases.txt << EOF
root: owner@example.com
user: user@example.com
EOF
cat > mail-aliases.txt << EOF
From: test@example.com
To: root, user, ann@example.com
Subject: Test

This is a test.
EOF

# Check that every local recipient is expanded, also one that directly
# follows an expanded alias
echo "Testing alias expansion of command line recipients"
../src/msmtp --host=::1 --port=12347 --from test@example.com \
	--aliases=aliases.txt root user ann@example.com < mail-aliases.txt
cmp -s <(echo owner@example.com user@example.com ann@example.com) out-aliases-rcpt.txt
../src/msmtp --host=::1 --port=12347 --from test@example.com \
	--aliases=aliases.txt user root < mail-aliases.txt
cmp -s <(echo user@example.com owner@example.com) out-aliases-rcpt.txt

echo "Testing alias expansion of recipients read from the mail"
../src/msmtp --host=::1 --port=12347 --from test@example.com \
	--aliases=aliases.txt --read-recipients < mail-aliases.txt
cmp -s <(echo owner@example.com user@example.com ann@example.com) out-aliases-rcpt.txt
