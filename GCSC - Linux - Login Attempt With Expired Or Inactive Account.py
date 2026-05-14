#Trạng thái: Đã test
#NOTE: 
- Cần bổ sung 1 số filed đặc trưng như tenant 
- Thêm lookup tương ứng để lấy src
- Ở đây em parse bằng app Unix and Linux có sẵn nên 1 số field app không parse được em sẽ dùng rex (Chỗ rex này sẽ nhờ anhtq theo đó mà parse ra field)

index=linux sourcetype=linux_secure "account" ("has expired" OR "inactive for")
| rename host as dest
| rex field=_raw "account\s+(?<user>\S+)\s+has\s+expired"
| eval user=coalesce(user, user_inactive),
    signature=case(
        searchmatch("has expired"), "expired_account_login_attempt",
        searchmatch("inactive for"), "inactive_account_login_attempt",
        1=1, "account_policy_denied"
    ),
    event_time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| where isnotnull(user)
| table dest user process signature event_time

# Thử đăng nhập bằng tài khoản đã hết hạn hoặc không hoạt động
#SAMPLE
'''
5/14/26
10:57:33.934 AM	
2026-05-14T10:57:33.934998+07:00 AGENT su[33334]: FAILED SU (to expired_user) splagent on pts/2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
10:57:33.933 AM	
2026-05-14T10:57:33.933673+07:00 AGENT su: pam_unix(su-l:account): account expired_user has expired (account expired)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
'''
