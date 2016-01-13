#!/usr/bin/python3

mon_param_names = {'conn', 'conn_bl', 'conn_wl', 'conn_fast', 'conn_tarpit', 'closed_conn_fail_client_early_write'}

names = mon_param_names.copy()
names.remove('conn')

print(names)
print(len(names))
print(mon_param_names)
