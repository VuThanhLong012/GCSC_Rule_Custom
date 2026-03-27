# Rule đã ổn => thay bằng macro linux_secure
index=vpa_os_linux sourcetype=linux_secure "groupmod[" "new gid:"
| lookup vpa_linux.csv hostname OUTPUT src_ip
| where isnotnull(src_ip)
| rename hostname as dest
| rex field=_raw "groupmod\[\d+\]:\s+group changed in /etc/group \(group (?<group>[A-Za-z0-9._-]+)/(?<old_gid>\d+), new gid: (?<new_gid>\d+)\)"
| where isnotnull(group) AND isnotnull(old_gid) AND isnotnull(new_gid)
| eval app="groupmod"
| eval action="modify"
| eval signature="local_group_gid_modified"
| eval first_seen=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table _time tenant src_ip dest group old_gid new_gid app action signature first_seen

# thay đổi thành viên group sẵn có
#SAMPLE
'''
Aug 30 20:39:03 aladdin groupmod[2450]: group changed in /etc/group (group test/501, new gid: 502)
Aug 30 20:39:03 aladdin groupmod[2450]: group changed in /etc/passwd (group test/501, new gid: 502)
'''