index=vpa_os_linux sourcetype=linux_secure # Rule đã ổn => thay bằng macro linux_secure
| search signature IN ("Failed password", "authentication failure", "Invalid user")
| lookup vpa_linux.csv hostname OUTPUT src_ip 
| where isnotnull(src_ip)
| bucket _time span=5m
| stats count as failed_attempts values(signature) as signatures values(src_port) as src_port by _time tenant src_ip user_name
| where failed_attempts >= 5