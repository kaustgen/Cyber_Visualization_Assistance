# Penetration Test Notes - Target Network

# Host: web-server-05
    - IP Address: 192.168.1.200
        - Connects To: 192.168.1.101
        - Connects To: 192.168.1.100
    - MAC Address: aa:bb:cc:dd:ee:ff
    - OS: Ubuntu 22.04 LTS
## Vulnerabilities
- CVE-2025-1111 - Score: 7.8, Exploitable: true, Patched: false
- CVE-2022-2222 - Score: 5.4
- CVE-2021-2455

## Open Ports
- Port 80
    - Service: Nginx 2.5.6
        - Vulnerabilities
            - CVE-2024-5412 (Score 6.5), CVE-2021-5675
        - Users
            - www-data
                Password: Chocolate
- Port 443
    - Service: Nginx 2.5.5
        - Notes: Possible pass-the-hash attack
- Port 22
    - Service: OpenSSH 8.2p1

## Services
- cron
    - Notes: Scheduled task service, runs as root
    Users: cron_admin

### Users
- admin (Administrator privileges)
    - Password: wow!
- billy (user privileges)
    - Password: holy smokes

### Notes
This is a good target as it has many possible vulnerabilites, pay attention to the Nginx vulnerability especially

