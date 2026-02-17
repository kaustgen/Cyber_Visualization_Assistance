# Complex Penetration Test

## Host: production-web-01
**IP Address:** 10.0.1.50
**MAC Address:** aa:bb:cc:dd:ee:ff
**Operating System:** Ubuntu 22.04 LTS

### Vulnerabilities
- CVE-2023-12345 - Score: 9.8, Exploitable: true, Patched: false
  - Notes: Critical RCE vulnerability in kernel
- CVE-2023-54321 - Score: 6.5, Exploitable: false, Patched: true
  - Notes: Patched privilege escalation

### Open Ports
- Port 22
  - Service: OpenSSH 8.9
    - Notes: SSH with key-based auth only
- Port 80
  - Service: nginx 1.22.0
    - Vulnerabilities: CVE-2023-11111 (Score: 7.5, Exploitable: true)
    - Notes: Reverse proxy to backend services
- Port 443
  - Service: nginx 1.22.0
    - Notes: SSL/TLS with Let's Encrypt
- Port 3306
  - Service: MySQL 8.0.32
    - Vulnerabilities: CVE-2023-22222 (Score: 8.1, Exploitable: true, Patched: false)
    - Notes: Database with external access enabled
    - Users: db_admin (Administrator), app_user (Limited)

### Services
- systemd
  - Notes: Init system
- docker
  - Notes: Container runtime
  - Users: docker_user (Standard)

### Users
- root (Administrator)
- web_admin (Administrator)
  - Has Access: nginx, MySQL
- deploy_user (Standard)
  - Has Access: docker
- app_service (Limited service account)

### Notes
Production web server with multiple vulnerabilities. High priority for patching. Connected to internal database network.

---

## Host: internal-db-01
**IP Address:** 10.0.1.100
  **Connects To:** 10.0.1.50
**MAC Address:** ff:ee:dd:cc:bb:aa
**Operating System:** CentOS 8

### Vulnerabilities
- CVE-2023-99999 - Score: 7.0, Exploitable: false, Patched: true

### Open Ports
- Port 5432
  - Service: PostgreSQL 14.2
    - Vulnerabilities: CVE-2023-88888 (Score: 9.0, Exploitable: true, Patched: false)
    - Notes: Primary application database
    - Users: postgres (Administrator), readonly_user (Read-only)

### Users
- Administrator (Full control)
  - Has Access: PostgreSQL
- backup_service (Backup account)

### Notes
Internal database server. Only accessible from 10.0.1.0/24 network. Requires immediate patching for PostgreSQL CVE.
