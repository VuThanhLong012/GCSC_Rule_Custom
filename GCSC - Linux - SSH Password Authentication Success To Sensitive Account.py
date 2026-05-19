#Trạng thái: Đã test
#NOTE: 
- Cần bổ sung 1 số filed đặc trưng như tenant 
- Thêm lookup tương ứng để lấy src
- Ở đây em parse bằng app Unix and Linux có sẵn nên 1 số field app không parse được em sẽ dùng rex (Chỗ rex này sẽ nhờ anhtq theo đó mà parse ra field)

index=linux sourcetype=linux_secure 
| search signature="Accepted password" process="sshd"
| rename host as dest, user_name as user
| search user IN ("root", "admin", "oracle", "postgres", "mysql", "mongodb", "redis", "nginx", "apache", "tomcat", "jenkins", "splunk", "zabbix", "backup", "deploy", "ansible") OR user="svc_*"
| eval first_seen=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table src_ip dest src_port user process action signature first_seen

# Bắt khi một account nhạy cảm đăng nhập SSH thành công bằng password thay vì key
#SAMPLE
'''
5/14/26
12:03:50.892 PM	
2026-05-14T12:03:50.892848+07:00 AGENT systemd-logind[1095]: Removed session 26.
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
12:03:50.882 PM	
2026-05-14T12:03:50.882630+07:00 AGENT systemd-logind[1095]: Session 26 logged out. Waiting for processes to exit.
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
12:03:50.869 PM	
2026-05-14T12:03:50.869778+07:00 AGENT sshd[34230]: pam_unix(sshd:session): session closed for user root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
12:03:50.867 PM	
2026-05-14T12:03:50.867384+07:00 AGENT sshd[34230]: Disconnected from user root 127.0.0.1 port 46110
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
12:03:50.867 PM	
2026-05-14T12:03:50.867077+07:00 AGENT sshd[34230]: Received disconnect from 127.0.0.1 port 46110:11: disconnected by user
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
12:03:47.892 PM	
2026-05-14T12:03:47.892563+07:00 AGENT systemd-logind[1095]: New session 26 of user root.
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
12:03:47.876 PM	
2026-05-14T12:03:47.876080+07:00 AGENT sshd[34230]: pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
12:03:47.872 PM	
2026-05-14T12:03:47.872489+07:00 AGENT sshd[34230]: Accepted password for root from 127.0.0.1 port 46110 ssh2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
12:03:40.676 PM	
2026-05-14T12:03:40.676119+07:00 AGENT gdm-password]: gkr-pam: unlocked login keyring
'''

#Kỹ thuật khai thác: 
- T1078 (Valid Accounts). Admin hoặc hacker đăng nhập thành công vào các tài khoản nhạy cảm (như các tài khoản dịch vụ oracle, postgres hoặc root) bằng phương thức Mật khẩu tĩnh thay vì SSH Key.

#Impact: 
- Mật khẩu tĩnh rất dễ bị Sniffing, bị log lại ở các máy trạm hoặc bị dò quét trúng. Hành vi này làm tăng rủi ro hệ thống.

#Phương án xử lý cho Tier1 (Phần này em viết chưa chuẩn lắm nên cần được góp ý thêm ạ):
- Xác minh: Gửi ticket xem đó có phải là hành vi nghiệp vụ của khách hàng không.
- Cấu hình cứng: Chuyển cấu hình tài khoản đó sang trạng thái chỉ nhận SSH Key trong cấu hình SSH hoặc khóa mật khẩu của tài khoản đó (passwd -l <username>).
