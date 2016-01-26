#!/usr/bin/python

import os
import grp
import pwd
import sys
import json
import time
import daemon
import signal
import socket
import syslog
import lockfile
import requests
from setproctitle import setproctitle
from pprint import pprint

headers = { 'Password': 'q1' }
spams = ['spam101', 'spam102', 'spam103', 'spam104']

def send_to_graphite(message, graphite_server, graphite_port):

    sock = socket.socket()
    try:
        sock.connect((graphite_server, graphite_port))
        sock.sendall(message)
    except Exception as ex:
            template = "An exception of type {0} occured. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            print message
    sock.close()

def get_stat(spams):
    message = ''
    timestamp = int(time.time())
    for spam in spams:

        try:
            r = requests.get("http://%s.rambler.ru:11334/stat" % spam, headers=headers)
            j = json.loads(r.text)
            message = message + "%s %s %d\n" % ('servers.spam.%s.scanned' % spam, j['scanned'], timestamp)
            message = message + "%s %s %d\n" % ('servers.spam.%s.ham' % spam, j['ham_count'], timestamp)
            message = message + "%s %s %d\n" % ('servers.spam.%s.spam' % spam, j['spam_count'], timestamp)
            message = message + "%s %s %d\n" % ('servers.spam.%s.add_header' % spam, j['actions']['add header'], timestamp)
            message = message + "%s %s %d\n" % ('servers.spam.%s.no_action' % spam, j['actions']['no action'], timestamp)
            message = message + "%s %s %d\n" % ('servers.spam.%s.greylist' % spam, j['actions']['greylist'], timestamp)
            message = message + "%s %s %d\n" % ('servers.spam.%s.reject' % spam, j['actions']['reject'], timestamp)

        except requests.exceptions.ConnectionError:
            r.status_code = "Connection refused"
            syslog.syslog("ConnectionError to rspamd")

        except Exception as ex:
            template = "An exception of type {0} occured. Arguments:\n{1!r}"
            mess = template.format(type(ex).__name__, ex.args)
            syslog.syslog(mess)
    return message

def do_main():
    gid = grp.getgrnam('nogroup').gr_gid
    uid = pwd.getpwnam('nobody').pw_uid
    os.setuid(uid)
    while 1:
        message = get_stat(spams)
        send_to_graphite(message, 'localhost', 2003)
        time.sleep(30)

def do_terminate(signum, frame):
    syslog.syslog('Exiting...')
    sys.exit(0)

context = daemon.DaemonContext(
    working_directory='/nonexistent',
    umask=0o022,
#    pidfile=lockfile.FileLock('/var/run/rspamd_stat.pid'),
    )

context.signal_map = {
#     signal.SIGTERM: program_cleanup,
#     signal.SIGHUP: 'terminate',
    signal.SIGTERM: do_terminate,
#     signal.SIGUSR1: reload_program_config,
}

setproctitle('rspamd_stat')
syslog.syslog('Started.')

with context:
    do_main()