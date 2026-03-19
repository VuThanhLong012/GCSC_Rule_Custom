index=vpa_os_linux sourcetype=linux_secure # Rule đã ổn => thay bằng macro linux_secure
| search signature IN ("Failed password", "authentication failure", "Invalid user")
| lookup vpa_linux.csv hostname OUTPUT src_ip 
| where isnotnull(src_ip)
| bucket _time span=5m
| stats count as failed_attempts values(signature) as signatures values(src_port) as src_port dc(user_name) as targeted_users values(user_name) as user_name by _time tenant src_ip
| where failed_attempts >= 5 AND targeted_users >= 3