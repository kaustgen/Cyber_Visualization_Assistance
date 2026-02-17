# Penetration Test Notes - Target Network

## Host: web-server-01

**IP Address:** 192.168.1.100  
**MAC Address:** 00:0a:95:9d:68:16  
**Operating System:** Ubuntu 20.04 LTS

### Vulnerabilities
- CVE-2021-3156 - Score: 7.8, Exploitable: true, Patched: false
  - Notes: Sudo vulnerability affecting Ubuntu 20.04

### Open Ports
- Port 80
  - Service: Apache 2.4.41
    - Vulnerabilities: CVE-2021-44790 (Score: 6.5), CVE-2021-44224 (Score: 7.5, Exploitable: true)
    - Notes: Running HTTP with mod_lua enabled
- Port 443
  - Service: Apache 2.4.41
    - Notes: Running over HTTPS
- Port 22 - SSH (OpenSSH 8.2p1)

### Services
- cron
  - Notes: Scheduled task service, runs as root
  - Users: cron_admin (Administrator privileges)

### Users
- admin (Administrator privileges)
- www-data (Limited service account)
  - Has Access: Apache
- john.doe (Standard user)

### Notes
Initial reconnaissance shows this is the main web server. Apache is running with potential vulnerabilities that need further investigation.

---

## Host: database-server-01

**IP Address:** 192.168.1.101
  **Connects To:** 192.168.1.100 
**MAC Address:** 00:0a:95:9d:68:17  
**Operating System:** Windows Server 2019

### Vulnerabilities
- CVE-2023-21768 - Score: 7.0, Exploitable: false, Patched: true
  - Notes: Windows privilege escalation, patched in latest update

### Open Ports
- Port 3306
  - Service: MySQL 8.0.26
    - Vulnerabilities: CVE-2022-21245 (Score: 8.1, Exploitable: true, Patched: false)
    - Notes: Database service with privilege escalation vulnerability
    - Users: root (Administrator privileges), db_backup (Backup service account)
- Port 3389 - RDP (Remote Desktop Protocol)

### Users
- Administrator (Full control)
- backup_svc (Backup service account with elevated privileges)

### Notes
Database server with potential privilege escalation vulnerability. RDP is open which could be an attack vector.
