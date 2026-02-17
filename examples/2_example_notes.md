# Host: web-server-02 - 192.168.0.5
- Operating System: Ubuntu 20.04 LTS
## Open Ports
- 22
    - OpenSSH 8.2p1
- 80
    - Apache 2.4.41
- 443
    - Apache 2.4.41

## Services
- Apache 2.4.41
    - Users: www-data (administrator), non-data (user)
- MySQL 4.5
    - Users: mysql (administrator)
    - Vulnerabilities
        - CVE-2022-4444
            - File injection vulnerability

## Users
- billy (administrator)
- john (user)

## Vulnerabilities
- CVE-2021-3156
    - Sudo vulnerability affecting Ubuntu 20.04

## Notes
- Initial reconnaissance shows this is the main web server