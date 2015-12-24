#!/usr/bin/env bash

do_send_mail()
{
	sendmail 25volt@25volt.ru < 2.eml
}

if [ $# != 1 ]; then
    echo "Usage: tsendmail.sh <n_mails>"
    exit 1
fi

N_MAILS=$1
echo "Sending $N_MAILS mails"

for i in $(seq $N_MAILS); do
	do_send_mail
done

wait
