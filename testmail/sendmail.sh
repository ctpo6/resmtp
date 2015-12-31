#!/usr/bin/env bash

#
# Send mails in parallel using sendmail.
#

do_send_mail()
{
	sendmail 25volt@25volt.ru < 2.eml
}

if [ $# != 1 ]; then
    echo "Usage: sendmail.sh <mails>"
    exit 1
fi

MAILS=$1
echo "Sending $MAILS mails"

for i in $(seq $MAILS); do
	do_send_mail &
done

wait
