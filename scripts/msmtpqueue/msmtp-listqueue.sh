#!/usr/bin/env sh

QUEUEDIR=$HOME/.msmtpqueue

for i in $QUEUEDIR/*.mail; do
	grep -E -s --colour -h '(^From:|^To:|^Subject:)' "$i" || echo "No mail in queue";
	echo " "
done
