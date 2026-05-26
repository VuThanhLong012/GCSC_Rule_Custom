#Trạng thái: Đã test
#NOTE: 
- Cần bổ sung 1 số filed đặc trưng như tenant 
- Thêm lookup tương ứng để lấy src
- Ở đây em parse bằng app Unix and Linux có sẵn nên 1 số field app không parse được em sẽ dùng rex (Chỗ rex này sẽ nhờ anhtq theo đó mà parse ra field)

index=linux sourcetype=linux_secure process IN ("usermod", "gpasswd") ("add" AND "group")
| rex field=_raw "add\s+'(?<target_user>[^']+)'\s+to\s+(?:shadow\s+)?group\s+'(?<added_group>[^']+)'"
| search added_group IN ("wheel", "sudo", "adm", "admin", "root")
| stats 
    count as event_count, 
    values(added_group) as added_groups,
    earliest(_time) as first_time
    by host process pid target_user
| rename host as dest
| eval action="add",
    first_seen=strftime(first_time, "%Y-%m-%d %H:%M:%S")
| table dest process pid target_user added_groups action first_seen

# một tài khoản được thêm vào nhóm đặc quyền
#SAMPLE
'''
5/14/26
1:22:06.800 PM	
2026-05-14T13:22:06.800093+07:00 AGENT sudo: pam_unix(sudo:session): session closed for user root
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:22:06.790 PM	
2026-05-14T13:22:06.790144+07:00 AGENT usermod[36151]: add 'auditor' to shadow group 'sudo'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:22:06.790 PM	
2026-05-14T13:22:06.790029+07:00 AGENT usermod[36151]: add 'auditor' to group 'sudo'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:22:06.775 PM	
2026-05-14T13:22:06.775216+07:00 AGENT sudo: pam_unix(sudo:session): session opened for user root(uid=0) by splagent(uid=1000)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:22:06.772 PM	
2026-05-14T13:22:06.772402+07:00 AGENT sudo: splagent : TTY=pts/0 ; PWD=/home/splagent ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo auditor
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
1:22:01.967 PM	
2026-05-14T13:22:01.967846+07:00 AGENT CRON[36139]: pam_unix(cron:session): session closed for user splagent
'''

#Kỹ thuật khai thác: 
- T1098 (Account Manipulation). Kẻ tấn công sau khi vào hệ thống sẽ cố gắng sẽ dùng lệnh usermod -aG sudo/wheel <user> hoặc gpasswd để đưa một tài khoản thường (do chúng tạo ra hoặc tài khoản chúng kiểm soát) vào nhóm có quyền quản trị.

#Impact: 
- Tạo Backdoor hợp pháp để duy trì quyền truy cập lâu dài. Kẻ tấn công sau đó chỉ cần đăng nhập bằng user thường đó và thoải mái thực thi lệnh root qua sudo mà không cần phải khai thác lại bất kỳ lỗ hổng nào, trốn tránh các rule quét mã độc/webshell.

#Phương án xử lý cho Tier1 (Phần này em viết chưa chuẩn lắm nên cần được góp ý thêm ạ):
- Xác minh: Gửi ticket xác minh với khách hàng đây có phải hành vi nghiệp vụ hợp lệ không.
