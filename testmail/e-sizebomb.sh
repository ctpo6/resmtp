#!/usr/bin/expect -f
################################################################################
# e-sizebomb.sh
# Test: send mail with specified data size
################################################################################ 

proc run_test {sz} {
	puts "*********************************************************************"
	puts "* test: $sz"
	puts "*********************************************************************"

	set chunk_size 400000
	set cur_size 0

	spawn ./g 3 $chunk_size
	wait

	set f [open out.txt]
	set fdata [read $f]
	close $f

	set timeout 60

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
	send "Subject: bomb\r\r"

	# size bomb
	while {$sz == 0 || $cur_size < $sz} {
		send "$fdata"
		send "\r"
		
		# without sleep script crashes (internal buffers overflow?)
		sleep 1

		# cur_size += chunk_size
		set cur_size [expr {$cur_size + $chunk_size}]	

		puts "**** $cur_size"
	}
	
	send "\r.\r"
	expect {
		"250 2.0.0 Ok" {}
		"*" {}
	}
	send "quit\r"
	expect "221 2.0.0 Closing connection."
	expect eof
}


if {[llength $argv] != 1} {
	puts "usage: e-sizebomb.sh <size>"
	puts "    <size> - bomb size, bytes; 0 - unlimited"
	exit 1
}

set bomb_size [lindex $argv 0]

if {![string is integer $bomb_size] || $bomb_size < 0} {
	puts "The <size> param must be equal or greater than 0"
	exit 1
}

run_test $bomb_size

