#!/usr/bin/env sh

QUEUEDIR=$HOME/.msmtpqueue

for i in $QUEUEDIR/*.mail; do
	HEADERS=$(grep -E -s --colour=always -h '(^From:|^To:|^Subject:)' "$i" || echo "No mail in queue")
	echo "$HEADERS" | head -n 3 # Limited to three rows to avoid matches from the body.
	echo " "
done
