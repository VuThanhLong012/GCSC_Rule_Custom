#Trạng thái: Đã test
#NOTE: 
- Cần bổ sung 1 số filed đặc trưng như tenant 
- Thêm lookup tương ứng để lấy src
- Ở đây em parse bằng app Unix and Linux có sẵn nên 1 số field app không parse được em sẽ dùng rex (Chỗ rex này sẽ nhờ anhtq theo đó mà parse ra field)

index=linux sourcetype=linux_secure "Failed password" OR "invalid user"
| rename host as dest
| bucket _time span=5m
| stats 
    count as failed_attempts,
    dc(user_name) as targeted_users,
    values(user_name) as targeted_account_list,
    values(src_port) as src_ports,
    earliest(_time) as first_time,
    latest(_time) as last_time
    by _time src_ip dest action process
| where targeted_users >= 5
| eval first_seen=strftime(first_time,"%Y-%m-%d %H:%M:%S"),
    last_seen=strftime(last_time,"%Y-%m-%d %H:%M:%S")
| table src_ip dest targeted_users targeted_account_list failed_attempts process action first_seen last_seen


#SAMPLE LOG
```
5/14/26
11:30:05.044 AM	
2026-05-14T11:30:05.044059+07:00 AGENT sshd[33822]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1 
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:30:05.040 AM	
2026-05-14T11:30:05.040635+07:00 AGENT sshd[33822]: Connection closed by invalid user testuser 127.0.0.1 port 45244 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:30:03.707 AM	
2026-05-14T11:30:03.707538+07:00 AGENT sshd[33822]: Failed password for invalid user testuser from 127.0.0.1 port 45244 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:30:01.946 AM	
2026-05-14T11:30:01.946224+07:00 AGENT sshd[33822]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:30:01.093 AM	
2026-05-14T11:30:01.093007+07:00 AGENT CRON[33824]: pam_unix(cron:session): session closed for user root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:30:01.083 AM	
2026-05-14T11:30:01.083331+07:00 AGENT CRON[33824]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:30:00.153 AM	
2026-05-14T11:30:00.153732+07:00 AGENT sshd[33822]: Failed password for invalid user testuser from 127.0.0.1 port 45244 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:58.806 AM	
2026-05-14T11:29:58.806056+07:00 AGENT sshd[33822]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:56.962 AM	
2026-05-14T11:29:56.962744+07:00 AGENT sshd[33822]: Failed password for invalid user testuser from 127.0.0.1 port 45244 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:54.825 AM	
2026-05-14T11:29:54.825635+07:00 AGENT sshd[33822]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1 
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:54.825 AM	
2026-05-14T11:29:54.825286+07:00 AGENT sshd[33822]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:54.382 AM	
2026-05-14T11:29:54.382799+07:00 AGENT sshd[33822]: Invalid user testuser from 127.0.0.1 port 45244
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:54.147 AM	
2026-05-14T11:29:54.147063+07:00 AGENT sshd[33819]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1 
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:54.144 AM	
2026-05-14T11:29:54.144601+07:00 AGENT sshd[33819]: Connection closed by invalid user guest 127.0.0.1 port 45042 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:52.413 AM	
2026-05-14T11:29:52.413446+07:00 AGENT sshd[33819]: Failed password for invalid user guest from 127.0.0.1 port 45042 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:50.158 AM	
2026-05-14T11:29:50.158717+07:00 AGENT sshd[33819]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:49.570 AM	
2026-05-14T11:29:49.570794+07:00 AGENT sshd[33819]: Failed password for invalid user guest from 127.0.0.1 port 45042 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:47.730 AM	
2026-05-14T11:29:47.730480+07:00 AGENT sshd[33819]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:46.680 AM	
2026-05-14T11:29:46.680177+07:00 AGENT sshd[33819]: Failed password for invalid user guest from 127.0.0.1 port 45042 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:45.113 AM	
2026-05-14T11:29:45.113440+07:00 AGENT sshd[33819]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1 
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:45.112 AM	
2026-05-14T11:29:45.112288+07:00 AGENT sshd[33819]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:44.869 AM	
2026-05-14T11:29:44.869239+07:00 AGENT sshd[33819]: Invalid user guest from 127.0.0.1 port 45042
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:44.646 AM	
2026-05-14T11:29:44.646874+07:00 AGENT sshd[33812]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=backup
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:44.641 AM	
2026-05-14T11:29:44.641757+07:00 AGENT sshd[33812]: Connection closed by authenticating user backup 127.0.0.1 port 53850 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:43.189 AM	
2026-05-14T11:29:43.189476+07:00 AGENT sshd[33812]: Failed password for backup from 127.0.0.1 port 53850 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:38.820 AM	
2026-05-14T11:29:38.820894+07:00 AGENT sshd[33812]: Failed password for backup from 127.0.0.1 port 53850 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:35.912 AM	
2026-05-14T11:29:35.912368+07:00 AGENT sshd[33812]: Failed password for backup from 127.0.0.1 port 53850 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:34.522 AM	
2026-05-14T11:29:34.522726+07:00 AGENT sshd[33812]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=backup
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:33.557 AM	
2026-05-14T11:29:33.557318+07:00 AGENT sshd[33809]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1 
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:33.554 AM	
2026-05-14T11:29:33.554724+07:00 AGENT sshd[33809]: Connection closed by invalid user webmaster 127.0.0.1 port 49214 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:31.377 AM	
2026-05-14T11:29:31.377006+07:00 AGENT sshd[33809]: Failed password for invalid user webmaster from 127.0.0.1 port 49214 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:29.007 AM	
2026-05-14T11:29:29.007597+07:00 AGENT sshd[33809]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:27.696 AM	
2026-05-14T11:29:27.696492+07:00 AGENT sshd[33809]: Failed password for invalid user webmaster from 127.0.0.1 port 49214 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:25.876 AM	
2026-05-14T11:29:25.876108+07:00 AGENT sshd[33809]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:24.595 AM	
2026-05-14T11:29:24.595015+07:00 AGENT sshd[33809]: Failed password for invalid user webmaster from 127.0.0.1 port 49214 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:23.049 AM	
2026-05-14T11:29:23.049031+07:00 AGENT sshd[33809]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1 
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:23.048 AM	
2026-05-14T11:29:23.048690+07:00 AGENT sshd[33809]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:20.639 AM	
2026-05-14T11:29:20.639684+07:00 AGENT sshd[33809]: Invalid user webmaster from 127.0.0.1 port 49214
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:20.453 AM	
2026-05-14T11:29:20.453265+07:00 AGENT sshd[33803]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1 
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:20.453 AM	
2026-05-14T11:29:20.453015+07:00 AGENT sshd[33803]: Connection closed by invalid user admin 127.0.0.1 port 44770 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:20.382 AM	
2026-05-14T11:29:20.382557+07:00 AGENT sshd[33803]: Failed password for invalid user admin from 127.0.0.1 port 44770 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:18.189 AM	
2026-05-14T11:29:18.189431+07:00 AGENT sshd[33803]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:16.775 AM	
2026-05-14T11:29:16.775454+07:00 AGENT sshd[33803]: Failed password for invalid user admin from 127.0.0.1 port 44770 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:15.661 AM	
2026-05-14T11:29:15.661720+07:00 AGENT sshd[33803]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:14.059 AM	
2026-05-14T11:29:14.059739+07:00 AGENT sshd[33803]: Failed password for invalid user admin from 127.0.0.1 port 44770 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:12.023 AM	
2026-05-14T11:29:12.023370+07:00 AGENT sshd[33803]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1 
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:12.022 AM	
2026-05-14T11:29:12.022097+07:00 AGENT sshd[33803]: pam_unix(sshd:auth): check pass; user unknown
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:11.056 AM	
2026-05-14T11:29:11.056864+07:00 AGENT sshd[33803]: Invalid user admin from 127.0.0.1 port 44770
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:29:07.133 AM	
2026-05-14T11:29:07.133567+07:00 AGENT gdm-password]: gkr-pam: unlocked login keyring
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:25:01.069 AM	
2026-05-14T11:25:01.069846+07:00 AGENT CRON[33697]: pam_unix(cron:session): session closed for user root
```
