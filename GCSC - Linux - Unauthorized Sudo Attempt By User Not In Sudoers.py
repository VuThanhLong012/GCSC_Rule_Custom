#Trạng thái: Đã test
#NOTE: 
- Cần bổ sung 1 số filed đặc trưng như tenant 
- Thêm lookup tương ứng để lấy src
- Ở đây em parse bằng app Unix and Linux có sẵn nên 1 số field app không parse được em sẽ dùng rex (Chỗ rex này sẽ nhờ anhtq theo đó mà parse ra field)

index=linux sourcetype=linux_secure "user NOT in sudoers"
| rex field=_raw "sudo:\s+(?<src_user>[^ ]+)\s+:"
| stats 
    count as unauthorized_sudo_attempts,
    values(COMMAND) as COMMAND,
    values(PWD) as PWD,
    values(TTY) as TTY,
    values(USER) as USER,
    earliest(_time) as first_time,
    latest(_time) as last_time
    by host src_user
| where unauthorized_sudo_attempts >= 5
| rename host as dest
| eval first_seen=strftime(first_time,"%Y-%m-%d %H:%M:%S"),
    last_seen=strftime(last_time,"%Y-%m-%d %H:%M:%S")
| table dest src_user USER unauthorized_sudo_attempts COMMAD PWD TTY first_seen last_seen

# một user 5 lần trở lên thực hiện sudo nhưng bị từ chối vì không nằm trong sudoers
#SAMPLE
'''
5/14/26
1:16:22.440 PM	
2026-05-14T13:16:22.440662+07:00 AGENT CRON[35926]: pam_unix(cron:session): session closed for user splagent
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:16:13.788 PM	
2026-05-14T13:16:13.788124+07:00 AGENT sudo: testuser : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=ls/root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:16:10.111 PM	
2026-05-14T13:16:10.111522+07:00 AGENT sudo: testuser : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=ls/root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:16:05.815 PM	
2026-05-14T13:16:05.815674+07:00 AGENT sudo: testuser : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=ls/root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:16:02.777 PM	
2026-05-14T13:16:02.777871+07:00 AGENT sudo: testuser : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=ls/root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:16:01.379 PM	
2026-05-14T13:16:01.379365+07:00 AGENT CRON[35927]: pam_unix(cron:session): session closed for user splagent
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:16:01.364 PM	
2026-05-14T13:16:01.364070+07:00 AGENT CRON[35925]: pam_unix(cron:session): session closed for user splagent
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:16:01.355 PM	
2026-05-14T13:16:01.355233+07:00 AGENT CRON[35926]: pam_unix(cron:session): session opened for user splagent(uid=1000) by splagent(uid=0)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:16:01.353 PM	
2026-05-14T13:16:01.353966+07:00 AGENT CRON[35927]: pam_unix(cron:session): session opened for user splagent(uid=1000) by splagent(uid=0)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:16:01.346 PM	
2026-05-14T13:16:01.346339+07:00 AGENT CRON[35925]: pam_unix(cron:session): session opened for user splagent(uid=1000) by splagent(uid=0)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:15:58.174 PM	
2026-05-14T13:15:58.174647+07:00 AGENT sudo: testuser : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=ls/root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:15:51.897 PM	
2026-05-14T13:15:51.897721+07:00 AGENT sudo: testuser : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=ls/root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:15:43.178 PM	
2026-05-14T13:15:43.178828+07:00 AGENT gdm-password]: gkr-pam: unlocked login keyring
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
'''

#Kỹ thuật khai thác: 
- T1548.003 (Abuse Privilege Escalation Mechanism: Sudo and Su). Thường xảy ra sau khi hacker chiếm được quyền của một tài khoản thường (ví dụ: thông qua lỗ hổng Web tạo Webshell chạy dưới quyền user). Hacker sẽ cố gắng gõ lệnh sudo -l hoặc sudo su để kiểm tra và leo quyền.

#Impact: 
- Đây có thể là phát hiện cho thấy tài khoản thường đó đang bị điều khiển bởi một thực thể độc hại (hoặc hành vi quá giới hạn cho phép). 

#Phương án xử lý cho Tier1 (Phần này em viết chưa chuẩn lắm nên cần được góp ý thêm ạ):
- Xác minh: Gửi ticket xem đó có phải là hành vi nghiệp vụ của khách hàng không.
- Kiểm tra tiến trình: Rà soát các kết nối mạng hiện thời và các tiến trình đang chạy của user đó để tìm kiếm Reverse Shell hoặc Webshell độc hại.
