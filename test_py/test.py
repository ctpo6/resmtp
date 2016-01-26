#!/usr/bin/python3

import os
import platform
import socket

print(socket.gethostname())
print(socket.getfqdn(socket.gethostname()))
print(os.uname())
print(platform.uname())
print(platform.node())

host_name = "resmtp.mail.rambler.ru"
print(host_name.split('.', maxsplit=1))

