# Rule đã ổn => thay bằng macro linux_secure
index=vpa_os_linux sourcetype=linux_secure signature="Failed password"  
| lookup vpa_linux.csv hostname OUTPUT src_ip
| where isnotnull(src_ip)
| rename hostname as dest
| bucket _time span=5m
| stats 
    count as failed_attempts
    earliest(_time) as first_time
    latest(_time) as last_time
    values(dest) as dest_host
    values(src_port) as src_ports
    by _time tenant src_ip user_name
| where failed_attempts >= 5
| eval first_seen=strftime(first_time,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_time,"%Y-%m-%d %H:%M:%S")
| table _time tenant src_ip user_name failed_attempts first_seen last_seen dest_host src_ports
