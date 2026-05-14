#Trạng thái: Đã test
#NOTE: 
- Cần bổ sung 1 số filed đặc trưng như tenant 
- Thêm lookup tương ứng để lấy src
- Ở đây em parse bằng app Unix and Linux có sẵn nên 1 số field app không parse được em sẽ dùng rex (Chỗ rex này sẽ nhờ anhtq theo đó mà parse ra field)

index=linux sourcetype=linux_secure "groupmod" "new gid:" "/etc/group"
| rename host as dest
| rex field=_raw "group\s+\(group\s+(?<group>[^/]+)/(?<old_gid>\d+),\s+new\s+gid:\s+(?<new_gid>\d+)"
| eval first_seen=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table _time pid dest group old_gid new_gid process first_seen

#SAMPLE
'''
5/14/26
10:18:55.932 AM	
2026-05-14T10:18:55.932300+07:00 AGENT groupmod[32862]: group changed in /etc/passwd (group testgroup/1003, new gid: 2000)
host = AGENTsource = /var/log/auth.logsourcetype = linux_secure
5/14/26
10:18:55.932 AM	
2026-05-14T10:18:55.932003+07:00 AGENT groupmod[32862]: group changed in /etc/group (group testgroup/1003, new gid: 2000)
'''
