# Penetration Test Notes - Target Network

## Host: web-server-01

**IP Address:** 192.168.1.100  
**MAC Address:** 00:0a:95:9d:68:16  
**Operating System:** Ubuntu 20.04 LTS

### Open Ports
- Port 80 - HTTP (Apache 2.4.41)
- Port 443 - HTTPS (Apache 2.4.41)
- Port 22 - SSH (OpenSSH 8.2p1)

### Applications
- **Apache Web Server 2.4.41**
  - CVE-2021-44790 (mod_lua vulnerability)
  - CVE-2021-44224 (SSRF vulnerability)

- **MySQL Database 5.7.35**
  - No known CVEs

### Users Found
- admin (Administrator privileges)
- www-data (Limited service account)
- john.doe (Standard user)

### Notes
Initial reconnaissance shows this is the main web server. Apache is running with potential vulnerabilities that need further investigation.

---

## Host: database-server-01

**IP Address:** 192.168.1.101
  **Connects To:** 192.168.1.100 
**MAC Address:** 00:0a:95:9d:68:17  
**Operating System:** Windows Server 2019

### Open Ports
- Port 3306 - MySQL
- Port 3389 - RDP (Remote Desktop)

### Applications
- **MySQL 8.0.26**
  - CVE-2022-21245 (Privilege escalation)

### Users Found
- Administrator (Full control)
- backup_svc (Backup service account with elevated privileges)

### Notes
Database server with potential privilege escalation vulnerability. RDP is open which could be an attack vector.
