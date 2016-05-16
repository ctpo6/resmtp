#!/usr/bin/expect -f

proc run_test {sz} {
	puts "*********************************************************************"
	puts "* test: $sz"
	puts "*********************************************************************"
	
	spawn ./g 1 $sz
	wait

	set f [open out.txt]
	set fdata [read $f]
	close $f

	set timeout 30

	spawn telnet resmtp.mail.rambler.ru 25
	sleep 1

	expect "220 resmtp.mail.rambler.ru Ok"
	send "EHLO me\r"
	expect "250-STARTTLS"
	send "HELO me\r"
	expect "250 resmtp.mail.rambler.ru"
	send "mail from: <yuri.epstein@rambler.ru>\r"
	expect "250 2.1.0 <yuri.epstein@rambler.ru> ok"
	send "rcpt to: <25volt@25volt.ru>\r"
	expect "250 2.1.5 <25volt@25volt.ru> recipient ok"
	send "data\r"
	expect "354 Enter mail data, end with <CRLF>.<CRLF>"
	send "From: <yuri.epstein@rambler.ru>\r"
	send "To: <25volt@25volt.ru>\r"
	send "Subject: $sz\r\r"
	send "$fdata"
	send "\r.\r"
	expect "250 2.0.0 Ok"
	send "quit\r"
	expect "221 2.0.0 Closing connection."
	expect eof
}


if {[llength $argv] != 1} {
	puts "usage: e-size.sh <size>"
	exit 1
}

set data_size [lindex $argv 0]

if {![string is integer $data_size] || $data_size < 1} {
	puts "The <size> param must be a positive integer"
	exit 1
}

run_test $data_size

