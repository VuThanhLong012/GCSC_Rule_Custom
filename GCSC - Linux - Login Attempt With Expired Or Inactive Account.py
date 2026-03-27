# Rule đã ổn => thay bằng macro linux_secure
index=vpa_os_linux sourcetype=linux_secure
("error: PAM: User account has expired for" OR "inactive for" "denied")
| lookup vpa_linux.csv hostname OUTPUT src_ip
| where isnotnull(src_ip)
| rename hostname as dest, user_name as user
| rex field=_raw "error: PAM: User account has expired for (?<user_expired>\S+) from (?<src>\d{1,3}(?:\.\d{1,3}){3})"
| rex field=_raw "pam_lastlog\([^)]+\): user (?<user_inactive>\S+) inactive for (?<inactive_days>\d+) days - denied"
| eval user=coalesce(user, user_expired, user_inactive)
| eval app=case(
    like(_raw,"%sshd[%"),"sshd",
    like(_raw,"%login[%"),"login",
    1=1,"pam"
)
| eval signature=case(
    like(_raw,"%User account has expired%"),"expired_account_login_attempt",
    like(_raw,"%inactive for%") AND like(_raw,"%denied%"),"inactive_account_login_attempt",
    1=1,"account_policy_denied"
)
| eval action="blocked"
| eval event_time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table _time tenant src_ip dest src user inactive_days app action signature event_time

# Thử đăng nhập bằng tài khoản đã hết hạn hoặc không hoạt động
#SAMPLE
'''
Mar 27 16:22:01 server1 sshd[22155]: error: PAM: User account has expired for testuser from 203.0.113.55
Mar 27 16:25:40 server2 sshd[22901]: pam_lastlog(sshd:account): user weaverw inactive for 71 days - denied
'''