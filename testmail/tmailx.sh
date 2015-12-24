#!/usr/bin/env bash

do_send_mail()
{
	mailx -r "yuri.epstein@rambler.ru" -s "test" -S smtp="inmx1.mail.rambler.ru:25" 25volt@25volt.ru < ./mail1.txt
}

if [ $# != 1 ]; then
    echo "Usage: tmailx.sh <n_mails>"
    exit 1
fi

N_MAILS=$1

echo "Sending $N_MAILS mails"

# start N jobs in parallel
for i in $(seq $N_MAILS); do
	do_send_mail &
done

wait

