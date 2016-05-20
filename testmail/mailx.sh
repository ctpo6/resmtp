#!/usr/bin/env bash

#
# Send mails in parallel using mailx.
#

do_send_mail()
{
	mailx -r "yuri.epstein@rambler.ru" -s "test_starttls" -S smtp="resmtp.mail.rambler.ru:25" -S smtp-use-starttls -S ssl-verify=ignore 25volt@25volt.ru < $MAIL_FILE
#	mailx -r "yuri.epstein@rambler.ru" -s "test_starttls" -S smtp="resmtp.mail.rambler.ru:25" 25volt@25volt.ru < $MAIL_FILE
}

if [ $# != 2 ]; then
	echo "Usage: mailx.sh <n> <file>"
	exit 1
fi

MAILS=$1
MAIL_FILE=$2

echo "Sending $MAILS mails..."

# start N jobs in parallel
for i in $(seq $MAILS); do
	do_send_mail &
done

wait

