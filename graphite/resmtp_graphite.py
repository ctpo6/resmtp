#!/usr/bin/python3

import os
import pwd
import sys
# import json
import time
import daemon
import signal
import socket
import syslog
# import lockfile
# import requests
from setproctitle import setproctitle
# from pprint import pprint

resmtp_addr = ('localhost', 11311)
graphite_addr = ('sherlock.mail.rambler.ru', 2003)
poll_timeout = 30   # resmtp poll timeout, seconds

# monitoring params which we have interest in
mon_param_names = {'conn', 'conn_bl', 'conn_wl', 'conn_fast', 'conn_tarpit', 'closed_conn_fail_client_early_write'}


def send_to_graphite(msg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect(graphite_addr)
        sock.sendall(msg.encode('ascii'))

    except Exception as e:
        t = "ERROR: exception {0}:\n{1!r}"
        s = t.format(type(e).__name__, e.args)
        syslog.syslog(s)

    sock.close()


def get_stat():
    msg = ''
    timestamp = int(time.time())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect(resmtp_addr)
        names = mon_param_names.copy()
        for line in sock.makefile('r', 1):
            line = line.rstrip()    # remove trailing '\n'
            first_word_in_line = line.partition(' ')[0]
            if first_word_in_line in names:
                msg += "resmtp.%s %d\n" % (line, timestamp)
                names.remove(first_word_in_line)
                # no need to continue reading the data: all params were found
                if not names:
                    break

    except Exception as e:
        t = "ERROR: exception {0}:\n{1!r}"
        s = t.format(type(e).__name__, e.args)
        syslog.syslog(s)

    sock.close()

    return msg


def do_main():
    # gid = grp.getgrnam('nogroup').gr_gid
    uid = pwd.getpwnam('nobody').pw_uid
    os.setuid(uid)

    while 1:
        msg = get_stat()
        if msg:
            print(msg)
            send_to_graphite(msg)
        else:
            print("*** can't get data from resmtp ***")
        time.sleep(poll_timeout)


def do_terminate(signum, frame):
    syslog.syslog('Exiting...')
    sys.exit(0)


# context = daemon.DaemonContext(
#     # working_directory='/nonexistent',
#     umask=0o022,
#     # pidfile=lockfile.FileLock('/var/run/rspamd_stat.pid'),
#     )
#
# context.signal_map = {
#     # signal.SIGTERM: program_cleanup,
#     # signal.SIGHUP: 'terminate',
#     signal.SIGTERM: do_terminate,
#     # signal.SIGUSR1: reload_program_config,
# }

setproctitle('resmtp_graphite')
syslog.syslog('started')

# with context:
#    do_main()

do_main()
