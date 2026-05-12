# hestia-security

Security hardening, monitoring and incident response scripts for **HestiaCP** servers (Ubuntu/Debian, nginx + PHP-FPM).

## Quick Install

```bash
git clone https://github.com/romangrinev/hestia-security.git /root/server-security
cd /root/server-security
cp security-audit.env.example /etc/security-audit.env
nano /etc/security-audit.env   # fill in your API key and email
bash install.sh
```

## Scripts

| Script | When | Description |
|--------|------|-------------|
| `01-security-audit.sh` | daily at 3:00 AM | Full audit: webshells, cron, SSH logins, processes, modified files, binary integrity. Sends email report. |
| `02-git-cleanup.sh` | manual | Resets all git repositories (`git checkout -- . && git clean -fd`) to remove injected files. |
| `03-hardening.sh` | manual (once) | PHP hardening, SSH lockdown, fail2ban setup, file permissions, inotifywait monitoring, nginx security blocks. |
| `04-git-auto-restore.sh` | every 6 hours | Automatically reverts modified git repos and sends an email alert. |

## Configuration

```bash
# /etc/security-audit.env
RESEND_API_KEY="re_xxxxxxxx"          # Resend.com API key
RESEND_FROM="security@yourdomain.com" # verified sender domain in Resend
RESEND_TO="admin@youremail.com"       # alert recipient email
```

Scripts auto-detect HestiaCP users via `v-list-users`.  
To set the user list manually, uncomment the `USERS=` line at the top of any script.

## Manual Run

```bash
# Security audit (run immediately)
sudo bash /root/server-security/01-security-audit.sh 2>&1 | tee /tmp/audit.txt

# Hardening (run once on a new or freshly compromised server)
sudo bash /root/server-security/03-hardening.sh 2>&1 | tee /tmp/hardening.txt

# Git cleanup (after an incident — resets all repos to last committed state)
sudo bash /root/server-security/02-git-cleanup.sh 2>&1 | tee /tmp/cleanup.txt
```

## Requirements

- Ubuntu 20.04+ / Debian 11+
- HestiaCP
- `curl`, `git`, `inotify-tools`, `fail2ban`
- [Resend.com](https://resend.com) account (free up to 3,000 emails/month)

## Firewall (iptables)

After running `03-hardening.sh`, restrict SSH to your own IP:

```bash
# Allow SSH only from your IP
sudo iptables -R INPUT 10 -p tcp -s YOUR_IP --dport 22 -j ACCEPT

# Persist rules across reboots
sudo netfilter-persistent save
```

To whitelist your IP in fail2ban (so you can't be banned):

```bash
# In /etc/fail2ban/jail.local under [DEFAULT]:
ignoreip = 127.0.0.1/8 YOUR_IP
sudo systemctl restart fail2ban
```

`01-security-audit.sh` automatically checks iptables and alerts if:
- SSH is open to `0.0.0.0/0` (the entire internet)
- `INPUT` policy is not `DROP`
- MySQL is accessible externally
- fail2ban is not active

## Binary Integrity Checks

`01-security-audit.sh` includes checks for backdoored system binaries (section 8b).

This was motivated by a real incident: an attacker replaced `/usr/bin/su` with a statically-linked backdoor that harvested passwords by reading stdin before exec'ing `/bin/sh`. The backdoor was also removed from the dpkg package database to evade `dpkg --verify`.

The audit detects:
- SUID binaries that are **statically linked** (unusual for Ubuntu — all system binaries should be dynamic)
- ELF files with **no section headers** (sign of packing/obfuscation)
- Files **not registered in dpkg** (attacker removed them from the package database)
- **dpkg checksum mismatches**

## Nginx Security Blocks (Livewire)

`03-hardening.sh` generates per-site `nginx.ssl.conf_security` files (HestiaCP's extra nginx include mechanism).

For Laravel sites with Livewire, it adds:

```nginx
location = /livewire/update {
    if ($http_user_agent ~* "python-requests|curl|wget|libwww|Go-http") {
        return 403;
    }
    limit_req zone=livewire burst=30 nodelay;
    limit_req_status 429;
    try_files $uri /index.php?$query_string;
}
```

> **Note:** The `try_files` line is required. Without it, the exact-match `location = /livewire/update` block will return 404 even though PHP-FPM is configured at the server level — exact-match locations do not fall through.

## Cron (configured by `install.sh`)

```
0 3 * * *   root bash /root/server-security/01-security-audit.sh >> /var/log/security-audit.log 2>&1
0 */6 * * * root bash /root/server-security/04-git-auto-restore.sh >> /var/log/git-auto-restore.log 2>&1
```
