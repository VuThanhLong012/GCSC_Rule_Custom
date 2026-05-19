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
5/13/26
10:41:43.164 AM	
2026-05-14T10:41:43.164060+07:00 AGENT userdel[33100]: delete 'testuser_to_delete' from shadow group 'users'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/13/26
10:41:43.164 AM	
2026-05-14T10:41:43.164018+07:00 AGENT userdel[33100]: removed shadow group 'testuser_to_delete' owned by 'testuser_to_delete'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/13/26
10:41:43.163 AM	
2026-05-14T10:41:43.163951+07:00 AGENT userdel[33100]: removed group 'testuser_to_delete' owned by 'testuser_to_delete'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/13/26
10:41:43.161 AM	
2026-05-14T10:41:43.161280+07:00 AGENT userdel[33100]: delete 'testuser_to_delete' from group 'users'
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/13/26
10:41:43.160 AM	
2026-05-14T10:41:43.160996+07:00 AGENT userdel[33100]: delete user 'testuser_to_delete'
'''

#Kỹ thuật khai thác: 
- T1070 (Indicator Removal on Host) hoặc T1485 (Data Destruction). Kẻ tấn công sử dụng lệnh userdel để xóa tài khoản do chúng tạo ra trước đó nhằm xóa dấu vết tấn công, hoặc cố tình xóa tài khoản của Admin hợp pháp/Tài khoản dịch vụ.

#Impact:
- Giai đoạn rút lui: Làm mất dấu vết Forensics, gây khó khăn cho việc tra cứu log của user đó.
- Giai đoạn phá hoại: Làm gián đoạn hoạt động của các ứng dụng phụ thuộc vào tài khoản dịch vụ bị xóa, hoặc khóa đường truy cập của đội vận hành.

#Phương án xử lý cho Tier1 (Phần này em viết chưa chuẩn lắm nên cần được góp ý thêm ạ):
- Xác minh: Gửi Ticket xem có hoạt động xóa tài khoản hoặc nhân viên nghỉ việc hay không.
- Trace thêm: Xem ai (tài khoản nào) đã thực thi lệnh userdel.
