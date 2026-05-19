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
5/13/26
10:57:33.934 AM	
2026-05-14T10:57:33.934998+07:00 AGENT su[33334]: FAILED SU (to expired_user) splagent on pts/2
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/13/26
10:57:33.933 AM	
2026-05-14T10:57:33.933673+07:00 AGENT su: pam_unix(su-l:account): account expired_user has expired (account expired)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
'''

#Kỹ thuật khai thác: 
- T1078.003 (Valid Accounts: Local Accounts). Kẻ tấn công (có thể là cựu nhân viên hoặc hacker sở hữu bộ database mật khẩu cũ rò rỉ) cố gắng đăng nhập vào hệ thống bằng các tài khoản đã bị đánh dấu expired hoặc inactive trong file /etc/shadow.

#Impact: 
- Nguy cơ rò rỉ thông tin xác thực cũ. Đây là mối đe dọa từ nội bộ hoặc hệ thống đang bị rà quét tài khoản từ bên ngoài. Tuy đăng nhập thất bại do PAM chặn, nhưng nó chứng tỏ mật khẩu của tài khoản đó đã bị lộ.

#Phương án xử lý cho Tier1 (Phần này em viết chưa chuẩn lắm nên cần được góp ý thêm ạ):
- Xác định nguồn: Thu thập src_ip để biết cuộc tấn công đến từ nội bộ hay IP Public từ Internet.
- Gửi ticket xác minh: Cảnh báo cho chủ sở hữu cũ của tài khoản (nếu là nhân viên nội bộ) để họ kiểm tra lại các thiết bị cá nhân xem có bị lộ mật khẩu dùng chung không.
