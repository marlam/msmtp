#!/usr/bin/env bash

set -e

# Start an msmtpd that dumps the mail and the recipient lists so we can check them
echo "Starting msmtpd"
../src/msmtpd --interface=::1 --port=12346 \
	--command='cat > out-header-handling-mail.txt; echo > out-header-handling-rcpt.txt' &
MSMTPD_PID=$!
trap "kill $MSMTPD_PID" EXIT

# Input mail example
echo "Generating test mail"
cat > mail-header-handling.txt << EOF
From: Some Name <from@example.com>
X-Comment: Recipient address madness inspired by the RFC 2822 appendix
To: to1@example.com,
	=?utf-8?B?VGVzdCDDnHNlcg==?= <to2@example.com>, Some
	One <to3@example.com>,
Cc: to4, "A; \"Quoted\" Name" <to5@example.com>
To: A Group:Person 1 <to6@example.com>,to7@example.com,SomeOne <to8@example.com>;
Cc: Undisclosed recipients:;
To: "A Person: Personal Account" <to9@example.com>
To: Some(wonderful \) chap) <to10(his account)@localhost(this host)>
Cc:A Group(Some people)
     :Some Person <to11@(their's host.)example.com>,
              to12, 
	        Person <to13@localhost> (a friend); (the end of the group)
Bcc:(Empty list)(start)Undisclosed recipients  :(nobody(that I know))  ;
Bcc: bcc@example.com
Subject: Test

This is a test.
EOF
# This is the correct list of recipients listed in the mail:
echo "to1@example.com" \
	"to2@example.com" \
	"to3@example.com" \
	"to4" \
	"to5@example.com" \
	"to6@example.com" \
	"to7@example.com" \
	"to8@example.com" \
	"to9@example.com" \
	"to10@localhost" \
	"to11@example.com" \
	"to12" \
	"to13@localhost" \
	"bcc@example.com" > mail-header-handling-correct-recipients.txt

# Check if msmtp adds a correct From header
echo "Testing From header generation"
../src/msmtp --host=::1 --port=12346 \
	--set-from-header=on --from test@example.com recipient@example.com < mail-header-handling.txt
cmp -s <(echo "From: test@example.com") <(grep "^From: " out-header-handling-mail.txt)
../src/msmtp --host=::1 --port=12346 \
	--set-from-header=on --from test@example.com -F "Test User" recipient@example.com < mail-header-handling.txt
cmp -s <(echo "From: Test User <test@example.com>") <(grep "^From: " out-header-handling-mail.txt)
LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 ../src/msmtp --host=::1 --port=12346 \
	--set-from-header=on --from test@example.com -F "Test Üser" recipient@example.com < mail-header-handling.txt
cmp -s <(echo "From: =?utf-8?B?VGVzdCDDnHNlcg==?= <test@example.com>") <(grep "^From: " out-header-handling-mail.txt)

# Check if msmtp used the correct recipient from the command line
echo "Testing command line recipient"
cmp -s <(echo recipient@example.com) out-header-handling-rcpt.txt

# Check if msmtp extracts the correct envelope from and recipient addresses when asked
echo "Testing address extraction"
../src/msmtp --host=::1 --port=12346 \
	--set-from-header=on --read-envelope-from --read-recipients < mail-header-handling.txt
cmp -s <(echo "From: from@example.com") <(grep "^From: " out-header-handling-mail.txt)
cmp -s mail-header-handling-correct-recipients.txt out-header-handling-rcpt.txt

# Check if msmtp adds a Date header that agrees with the date command
echo "Testing Date header"
grep "^Date: " out-header-handling-mail.txt > /dev/null
if date --version > /dev/null 2>&1 ; then
	echo "Testing Date header format"
	TEST_DATE="`grep "^Date: " out-header-handling-mail.txt | sed -e 's/Date: //'`"
	cmp -s <(echo $TEST_DATE) <(date -R --date="$TEST_DATE")
fi

# Check if msmtp adds a Message-ID header
echo "Testing Message-ID header"
grep "^Message-ID: <.*@example.com>" out-header-handling-mail.txt > /dev/null

# Check if msmtp removed the Bcc headers
echo "Testing Bcc header removal"
cmp -s out-header-handling-mail.txt <(grep -v "^Bcc: " out-header-handling-mail.txt)
