# Rule đã ổn => thay bằng macro linux_secure
index=vpa_os_linux sourcetype=linux_secure ("usermod[" OR "gpasswd[")
| lookup vpa_linux.csv hostname OUTPUT src_ip
| where isnotnull(src_ip)
| rename hostname as dest
| rex field=_raw "(?<process>usermod|gpasswd)\[\d+\]:\s+(?:add|added)\s+'?(?<user>[A-Za-z0-9._-]+)'?\s+to\s+(?:shadow\s+)?group\s+'?(?<group>[A-Za-z0-9._-]+)'?"
| where isnotnull(user) AND match(group,"^(wheel|sudo|adm|admin)$")
| eval action="add"
| eval change_type="privileged_group_membership"
| eval first_seen=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table _time tenant src_ip dest process user group action change_type first_seen

# một tài khoản được thêm vào nhóm đặc quyền
#SAMPLE
'''
Mar 27 17:12:01 server1 usermod[24567]: add 'alice' to group 'wheel'
Mar 27 17:18:44 server2 gpasswd[25101]: added 'devops' to group 'sudo'
'''