#Trạng thái: Đã test
#NOTE: 
- Cần bổ sung 1 số filed đặc trưng như tenant 
- Thêm lookup tương ứng để lấy src
- Ở đây em parse bằng app Unix and Linux có sẵn nên 1 số field app không parse được em sẽ dùng rex (Chỗ rex này sẽ nhờ anhtq theo đó mà parse ra field)

index=linux sourcetype=linux_secure "Failed password"
| rename host as dest
| bucket _time span=5m
| stats 
    count as total_failed_attempts
    dc(user_name) as targeted_users
    values(user_name) as targeted_account_list
    values(src_port) as src_ports
    earliest(_time) as first_time
    by _time src_ip dest action process
| where total_failed_attempts >= 5 AND targeted_users <= 2
| eval first_seen=strftime(first_time,"%Y-%m-%d %H:%M:%S"),
    last_seen=strftime(last_time,"%Y-%m-%d %H:%M:%S")
| table src_ip dest targeted_account_list total_failed_attempts targeted_users process action first_seen


#SAMPLE LOG
```
5/14/26
11:12:57.555 AM	
2026-05-14T11:12:57.555079+07:00 AGENT sshd[33660]: PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:57.552 AM	
2026-05-14T11:12:57.552063+07:00 AGENT sshd[33660]: Connection closed by authenticating user root 127.0.0.1 port 52646 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:56.188 AM	
2026-05-14T11:12:56.188531+07:00 AGENT sshd[33660]: Failed password for root from 127.0.0.1 port 52646 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:51.897 AM	
2026-05-14T11:12:51.897844+07:00 AGENT sshd[33660]: Failed password for root from 127.0.0.1 port 52646 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:49.474 AM	
2026-05-14T11:12:49.474605+07:00 AGENT sshd[33660]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:48.019 AM	
2026-05-14T11:12:48.019195+07:00 AGENT sshd[33657]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:48.017 AM	
2026-05-14T11:12:48.017683+07:00 AGENT sshd[33657]: Connection closed by authenticating user root 127.0.0.1 port 40388 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:46.957 AM	
2026-05-14T11:12:46.957656+07:00 AGENT sshd[33657]: message repeated 2 times: [ Failed password for root from 127.0.0.1 port 40388 ssh2]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:37.771 AM	
2026-05-14T11:12:37.771121+07:00 AGENT sshd[33657]: Failed password for root from 127.0.0.1 port 40388 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:35.939 AM	
2026-05-14T11:12:35.939616+07:00 AGENT sshd[33657]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:34.025 AM	
2026-05-14T11:12:34.025516+07:00 AGENT sshd[33654]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:34.024 AM	
2026-05-14T11:12:34.024816+07:00 AGENT sshd[33654]: Connection closed by authenticating user root 127.0.0.1 port 43862 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:34.010 AM	
2026-05-14T11:12:34.010133+07:00 AGENT sshd[33654]: message repeated 2 times: [ Failed password for root from 127.0.0.1 port 43862 ssh2]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:25.441 AM	
2026-05-14T11:12:25.441418+07:00 AGENT sshd[33654]: Failed password for root from 127.0.0.1 port 43862 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:23.590 AM	
2026-05-14T11:12:23.590208+07:00 AGENT sshd[33654]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:22.607 AM	
2026-05-14T11:12:22.607390+07:00 AGENT sshd[33651]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:22.607 AM	
2026-05-14T11:12:22.607115+07:00 AGENT sshd[33651]: Connection closed by authenticating user root 127.0.0.1 port 42226 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:22.008 AM	
2026-05-14T11:12:22.008995+07:00 AGENT sshd[33651]: message repeated 2 times: [ Failed password for root from 127.0.0.1 port 42226 ssh2]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:14.867 AM	
2026-05-14T11:12:14.867952+07:00 AGENT sshd[33651]: Failed password for root from 127.0.0.1 port 42226 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:12.860 AM	
2026-05-14T11:12:12.860322+07:00 AGENT sshd[33651]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:12.439 AM	
2026-05-14T11:12:12.439411+07:00 AGENT sshd[33648]: PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:12.436 AM	
2026-05-14T11:12:12.436835+07:00 AGENT sshd[33648]: Connection closed by authenticating user root 127.0.0.1 port 37676 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:11.109 AM	
2026-05-14T11:12:11.109236+07:00 AGENT sshd[33648]: Failed password for root from 127.0.0.1 port 37676 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:08.005 AM	
2026-05-14T11:12:08.005892+07:00 AGENT sshd[33648]: Failed password for root from 127.0.0.1 port 37676 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:06.154 AM	
2026-05-14T11:12:06.154581+07:00 AGENT sshd[33648]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:04.253 AM	
2026-05-14T11:12:04.253252+07:00 AGENT sshd[33641]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:04.248 AM	
2026-05-14T11:12:04.248254+07:00 AGENT sshd[33641]: Connection closed by authenticating user root 127.0.0.1 port 58932 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:12:03.144 AM	
2026-05-14T11:12:03.144671+07:00 AGENT sshd[33641]: message repeated 2 times: [ Failed password for root from 127.0.0.1 port 58932 ssh2]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:56.049 AM	
2026-05-14T11:11:56.049823+07:00 AGENT sshd[33641]: Failed password for root from 127.0.0.1 port 58932 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:53.982 AM	
2026-05-14T11:11:53.982591+07:00 AGENT sshd[33641]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:49.241 AM	
2026-05-14T11:11:49.241679+07:00 AGENT sshd[33591]: Connection closed by authenticating user root 127.0.0.1 port 40964 [preauth]
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:49.235 AM	
2026-05-14T11:11:49.235600+07:00 AGENT sshd[33591]: Failed password for root from 127.0.0.1 port 40964 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:46.062 AM	
2026-05-14T11:11:46.062185+07:00 AGENT sshd[33591]: Failed password for root from 127.0.0.1 port 40964 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:43.699 AM	
2026-05-14T11:11:43.699234+07:00 AGENT sshd[33591]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:40.797 AM	
2026-05-14T11:11:40.797215+07:00 AGENT systemd-logind[1095]: Removed session 18.
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:40.789 AM	
2026-05-14T11:11:40.789780+07:00 AGENT systemd-logind[1095]: Session 18 logged out. Waiting for processes to exit.
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:40.771 AM	
2026-05-14T11:11:40.771307+07:00 AGENT sshd[33498]: pam_unix(sshd:session): session closed for user root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:40.770 AM	
2026-05-14T11:11:40.770511+07:00 AGENT sshd[33498]: Disconnected from user root 127.0.0.1 port 40960
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:40.769 AM	
2026-05-14T11:11:40.769751+07:00 AGENT sshd[33498]: Received disconnect from 127.0.0.1 port 40960:11: disconnected by user
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:36.429 AM	
2026-05-14T11:11:36.429676+07:00 AGENT systemd-logind[1095]: New session 18 of user root.
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:36.413 AM	
2026-05-14T11:11:36.413381+07:00 AGENT sshd[33498]: pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:36.409 AM	
2026-05-14T11:11:36.409448+07:00 AGENT sshd[33498]: Accepted password for root from 127.0.0.1 port 40960 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:32.217 AM	
2026-05-14T11:11:32.217364+07:00 AGENT sshd[33496]: Server listening on :: port 22.
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
11:11:32.217 AM	
2026-05-14T11:11:32.217032+07:00 AGENT sshd[33496]: Server listening on 0.0.0.0 port 22.
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
```

#Kỹ thuật khai thác: 
- T1110.001 (Brute Force: Password Password Guessing). Kẻ tấn công sử dụng các công cụ quét tự động chạy liên tục hàng trăm/hàng ngàn request đăng nhập với các mật khẩu phổ biến vào một tài khoản cố định (thường là root, admin, ubuntu).

#Impact: 
- Gây Log Flooding, tiêu tốn tài nguyên hệ thống (CPU/Băng thông). 
- Rủi ro cao, sẽ bị chiếm quyền nếu tài khoản đó vô tình đặt mật khẩu yếu hoặc chưa được Hardening.

#Phương án xử lý cho Tier1 (Phần này em viết chưa chuẩn lắm nên cần được góp ý thêm ạ):
- Trace: Chạy câu lệnh tương quan trên SIEM để xem ngay sau chuỗi log Failed password có dòng nào là Accepted publickey/password từ IP đó không (Để xác định cuộc tấn công đã thành công chưa).
- Chặn IP: Thực hiện block IP nguồn trên Firewall.
