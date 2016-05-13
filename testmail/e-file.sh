#!/usr/bin/expect -f

if {[llength $argv] != 1} {
	puts "usage: e-file.sh <file>"
	exit 1
}


set fname [lindex $argv 0]
#puts "Send file: $fname"

set f [open $fname]
set fdata [read $f]
#puts "$fdata"

set timeout 30

spawn telnet resmtp.mail.rambler.ru 25
sleep 2

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
send "Subject: $fname\r\r"
send "$fdata"
send "\r.\r"
expect "250 2.0.0 Ok"
send "quit\r"
expect "221 2.0.0 Closing connection."
