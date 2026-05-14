#Trạng thái: Đã test
#NOTE: 
- Cần bổ sung 1 số filed đặc trưng như tenant 
- Thêm lookup tương ứng để lấy src
- Ở đây em parse bằng app Unix and Linux có sẵn nên 1 số field app không parse được em sẽ dùng rex (Chỗ rex này sẽ nhờ anhtq theo đó mà parse ra field)

index=linux sourcetype=linux_secure "userdel[" "delete user"
| rename host as dest, user_name as user
| eval first_seen=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table dest user process action first_seen

# Bắt khi một local user bị xóa
#SAMPLE
'''
5/14/26
10:41:43.164 AM	
2026-05-14T10:41:43.164060+07:00 AGENT userdel[33100]: delete 'testuser_to_delete' from shadow group 'users'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
10:41:43.164 AM	
2026-05-14T10:41:43.164018+07:00 AGENT userdel[33100]: removed shadow group 'testuser_to_delete' owned by 'testuser_to_delete'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
10:41:43.163 AM	
2026-05-14T10:41:43.163951+07:00 AGENT userdel[33100]: removed group 'testuser_to_delete' owned by 'testuser_to_delete'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
10:41:43.161 AM	
2026-05-14T10:41:43.161280+07:00 AGENT userdel[33100]: delete 'testuser_to_delete' from group 'users'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
10:41:43.160 AM	
2026-05-14T10:41:43.160996+07:00 AGENT userdel[33100]: delete user 'testuser_to_delete'
'''
