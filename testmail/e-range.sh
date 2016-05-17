#!/usr/bin/expect -f

proc run_test {sz} {
	puts "*********************************************************************"
	puts "* test: $sz"
	puts "*********************************************************************"
	
	spawn ./g 3 $sz
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
	send "\n\n\r\n\\\\r\r\r\rr\r"
	send "\r.\r"
#	expect "250 2.0.0 Ok"
	send "quit\r"
	expect "221 2.0.0 Closing connection."
	expect eof
}


if {[llength $argv] != 2} {
	puts "Usage: e-size.sh <size1> <size2>"
	puts "    where size1 <= size2"
	exit 1
}

set size1 [lindex $argv 0]
set size2 [lindex $argv 1]

if {![string is integer $size1] || $size1 < 1} {
	puts "The <size1> param must be a positive integer"
	exit 1
}
if {![string is integer $size2] || $size2 < 1} {
	puts "The <size2> param must be a positive integer"
	exit 1
}
if {!($size1 <= $size2)} {
	puts "The <size1> must be less then or equal to <size2>"
	exit 1
}

#set sz $size1

for {set sz $size1} {$sz <= $size2} {incr sz} {
	run_test $sz
}

