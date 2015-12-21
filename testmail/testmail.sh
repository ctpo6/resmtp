#!/bin/bash
mailx -v -r "yuri.epstein@rambler.ru" -s "test" -S smtp="inmx1.mail.rambler.ru:25" 25volt@25volt.ru < ./mail.txt
