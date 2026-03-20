# Rule đã ổn => thay bằng macro linux_secure
index=vpa_os_linux sourcetype=linux_secure
| search signature IN ("Failed password", "Invalid user")
| lookup vpa_linux.csv hostname OUTPUT src_ip
| where isnotnull(src_ip) AND isnotnull(user_name)
| bucket _time span=5m
| stats 
    count as failed_attempts
    dc(user_name) as targeted_users
    values(user_name) as targeted_account_list
    values(signature) as signatures
    earliest(_time) as first_time
    latest(_time) as last_time
    values(hostname) as src_host
    values(src_port) as src_ports
    by _time tenant src_ip
| where failed_attempts >= 5 AND targeted_users >= 3
| eval first_seen=strftime(first_time,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_time,"%Y-%m-%d %H:%M:%S")
| table _time tenant src_ip src_host src_ports failed_attempts targeted_users targeted_account_list signatures first_seen last_seen
