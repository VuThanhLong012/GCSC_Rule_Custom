# Rule đã ổn => thay bằng macro linux_secure
index=vpa_os_linux sourcetype=linux_secure signature="Accepted password"
| lookup vpa_linux.csv hostname OUTPUT src_ip
| where isnotnull(src_ip)
| rename hostname as dest, user_name as user
| where match(user,"^(root|admin|oracle|postgres|mysql|mongodb|redis|nginx|apache|tomcat|jenkins|splunk|zabbix|backup|deploy|ansible|svc_.*)$")
| rex field=_raw "Accepted\s+password\s+for\s+(?<user>\S+)\s+from\s+(?<src>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?<src_port>\d+)"
| where isnotnull(src)
| eval auth_method="password"
| eval app="sshd"
| eval action="success"
| eval signature="ssh_password_auth_success_to_sensitive_account"
| eval first_seen=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table _time tenant src_ip dest src src_port user auth_method app action signature first_seen

# Bắt khi một account nhạy cảm đăng nhập SSH thành công bằng password thay vì key
#SAMPLE
'''
May 21 20:22:28 slacker2 sshd[8813]: Accepted password for root from 192.168.20.185 port 1066 ssh2
'''