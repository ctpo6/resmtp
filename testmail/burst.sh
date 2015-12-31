#!/usr/bin/env bash

#
# Send mails in bursts with a timeout between them
#

MAIL_FILE="./mail.txt"

print_usage()
{
	echo "Usage: burst.sh <mails> <burst> <timeout>"
	echo "    <mails>    Total number of mails to send (>=0, 0 - infinite)"
	echo "    <burst>    Burst size - number of mails in the burst (>=1)"
	echo "    <timeout>  Timeout between bursts, seconds (>=0)"
}


do_send_mail()
{
	mailx -r "yuri.epstein@rambler.ru" -s "test" -S smtp="inmx1.mail.rambler.ru:25" 25volt@25volt.ru < $MAIL_FILE
}


################################################################################
# main
################################################################################

if (($# != 3)); then
  print_usage
	exit 1
fi

MAILS=$1
BURST=$2
TIMEOUT=$3

# TODO: check that arguments are numbers
if (($MAILS < 0)) || (($BURST < 1)) || (($TIMEOUT < 0)); then
	echo "Error: wrong argument value"
	print_usage
	exit 1
fi

if [ ! -f $MAIL_FILE ]; then
	echo "Error: mail file $MAIL_FILE doesn't exist"
	exit 1
fi

if ((MAILS > 0)); then
	echo "Sending $MAILS mails by $BURST at once, with a timeout of $TIMEOUT seconds:"
else
	echo "Sending mails by $BURST at once, with a timeout of $TIMEOUT seconds:"
fi

# send up to MAILS mails, or infinite if MAILS is 0
BURST_SIZE=$BURST
C_MAILS=0
while true; do
	# is MAILS is not 0, adjust BURST_SIZE to send no more than MAILS mails
	if ((MAILS > 0)); then
		((BURST_SIZE = MAILS - C_MAILS))
		if ((BURST_SIZE > BURST)); then
			BURST_SIZE=$BURST
		fi		
	fi

	# send BURST mails in parallel
	for i in $(seq $BURST_SIZE); do
		do_send_mail &
	done
	wait

	((C_MAILS += BURST_SIZE))

	# all mails sent?
	if ((MAILS > 0)) && ((C_MAILS >= MAILS)); then
		break
	fi
	
	echo $C_MAILS
	sleep $TIMEOUT
done

echo "Sent $C_MAILS mails"

