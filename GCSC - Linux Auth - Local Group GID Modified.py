#Trạng thái: Đã test
#NOTE: 
- Cần bổ sung 1 số filed đặc trưng như tenant 
- Thêm lookup tương ứng để lấy src
- Ở đây em parse bằng app Unix and Linux có sẵn nên 1 số field app không parse được em sẽ dùng rex (Chỗ rex này sẽ nhờ anhtq theo đó mà parse ra field)

index=linux sourcetype=linux_secure "groupmod" "new gid:" "/etc/group"
| rename host as dest
| rex field=_raw "group\s+\(group\s+(?<group>[^/]+)/(?<old_gid>\d+),\s+new\s+gid:\s+(?<new_gid>\d+)"
| eval first_seen=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table pid dest group old_gid new_gid process first_seen

#Thay đổi thành viên group sẵn có
#SAMPLE
'''
5/13/26
10:18:55.932 AM	
2026-05-14T10:18:55.932300+07:00 AGENT groupmod[32862]: group changed in /etc/passwd (group testgroup/1003, new gid: 2000)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/13/26
10:18:55.932 AM	
2026-05-14T10:18:55.932003+07:00 AGENT groupmod[32862]: group changed in /etc/group (group testgroup/1003, new gid: 2000)
'''

#Kỹ thuật khai thác: 
- T1098 (Account Manipulation). Kẻ tấn công sau khi vào hệ thống sẽ sử dụng lệnh groupmod hoặc can thiệp trực tiếp vào file /etc/group để sửa đổi GID của một nhóm thông thường thành 0 (ngang hàng với nhóm root).

#Impact:
- Đây là kỹ thuật leo thang đặc quyền ngầm và Defense Evasion. Một user thuộc nhóm thường lại có toàn quyền đọc/ghi vào các file hệ thống nhạy cảm của root mà không cần phải gõ lệnh sudo, lách qua các rule giám sát sudo thông thường.

#Phương án xử lý cho Tier1 (Phần này em viết chưa chuẩn lắm nên cần được góp ý thêm ạ):
- Xác minh: Kiểm tra xem đây có phải hoạt động nâng cấp hệ thống hoặc cài đặt phần mềm đặc thù của đội System Admin hay không.
