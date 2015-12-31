#!/usr/bin/env bash

#
# Send mails in parallel using mailx.
#

do_send_mail()
{
	mailx -r "yuri.epstein@rambler.ru" -s "test" -S smtp="inmx1.mail.rambler.ru:25" 25volt@25volt.ru < ./mail.txt
}

if [ $# != 1 ]; then
	echo "Usage: mailx.sh <mails>"
	exit 1
fi

MAILS=$1

echo "Sending $MAILS mails..."

# start N jobs in parallel
for i in $(seq $MAILS); do
	do_send_mail &
done

wait

