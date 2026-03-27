# Rule đã ổn => thay bằng macro linux_secure
index=vpa_os_linux sourcetype=linux_secure "sudo:" "user NOT in sudoers"
| lookup vpa_linux.csv hostname OUTPUT src_ip
| where isnotnull(src_ip)
| rename hostname as dest
| rex field=_raw "sudo:\s+(?<src_user>\S+)\s*:\s*user NOT in sudoers\s*;\s*TTY=(?<tty>[^;]+)\s*;\s*PWD=(?<pwd>[^;]+)\s*;\s*USER=(?<user>[^;]+)\s*;\s*COMMAND=(?<process>.+)$"
| where isnotnull(src_user) AND isnotnull(user) AND isnotnull(process)
| bucket _time span=10m
| stats
    count as unauthorized_sudo_attempts
    earliest(_time) as first_time
    latest(_time) as last_time
    values(process) as process
    values(tty) as tty
    values(pwd) as pwd
    by _time tenant dest src_ip src_user user
| where unauthorized_sudo_attempts >= 5
| eval first_seen=strftime(first_time,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_time,"%Y-%m-%d %H:%M:%S")
| table _time tenant dest src_ip src_user user unauthorized_sudo_attempts process tty pwd first_seen last_seen

# một user 5 lần trở lên thực hiện sudo nhưng bị từ chối vì không nằm trong sudoers
#SAMPLE
'''
Mar 27 10:14:21 server1 sudo: alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
Mar 27 10:15:02 server1 sudo: alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
'''