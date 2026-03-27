# Rule đã ổn => thay bằng macro linux_secure
index=vpa_os_linux sourcetype=linux_secure "userdel[" "delete user"
| lookup vpa_linux.csv hostname OUTPUT src_ip
| where isnotnull(src_ip)
| rename hostname as dest
| rex field=_raw "userdel\[\d+\]:\s+delete user [`'](?<user>[A-Za-z0-9._-]+)[`']"
| where isnotnull(user)
| eval app="userdel"
| eval action="delete"
| eval signature="local_user_deleted"
| eval first_seen=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table _time tenant src_ip dest user app action signature first_seen

# Bắt khi một local user bị xóa
#SAMPLE
'''
Feb 10 02:03:11 userdel[1516]: delete user `mike'
'''