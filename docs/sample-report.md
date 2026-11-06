# Linux security audit report

- Host: `grok-bot-vm-511282481`
- Generated (UTC): 2026-11-06T10:21:02Z
- Tool: linux-security-audit v1.0.0
- Mode: **read-only** (no system changes)

## Summary

| Severity | Count |
|----------|------:|
| PASS | 5 |
| INFO | 4 |
| WARN | 2 |
| FAIL | 0 |
| SKIP | 2 |

## Findings

### [INFO] Host identity
Hostname: `grok-bot-vm-511282481`
User: `box` (uid 1000)
OS: Debian GNU/Linux 13 (trixie)
Kernel: 6.12.94+
Audit version: 1.0.0
Started (UTC): 2026-11-06T10:21:02Z
Root privileges: no

### [PASS] UID 0 accounts
Only `root` has UID 0.

### [SKIP] Empty password accounts
Cannot read /etc/shadow (needs root). Skipped without elevating privileges.

### [PASS] Permissions on /etc/shadow
Mode `640`, owner `root:shadow`.

### [SKIP] SSH daemon configuration
Cannot read /etc/ssh/sshd_config.

### [PASS] SSH private key permissions
No overly open private key modes found among paths that could be inspected.

### [PASS] ~/.ssh directory modes
Inspected home .ssh directories look appropriately restricted (or none readable).

### [PASS] World-writable files in sensitive paths
No world-writable regular files found under /etc /bin /sbin /usr/bin /usr/sbin /boot (best-effort, non-root may miss some).

### [WARN] Unusual SUID/SGID binaries
Binaries with SUID/SGID not on the small expected allow-list (capped):
```
/usr/bin/chage (2755 root:shadow)
/usr/bin/expiry (2755 root:shadow)
```
Review these; many are legitimate. This audit does not remove or change them.

### [INFO] Listening ports
Current listening sockets (read-only snapshot, capped):
```
tcp LISTEN 0      100      0.0.0.0:6081  0.0.0.0:*
tcp LISTEN 0      100      0.0.0.0:6080  0.0.0.0:*
tcp LISTEN 0      10     127.0.0.1:9223  0.0.0.0:*
tcp LISTEN 0      128    127.0.0.1:8791  0.0.0.0:*
tcp LISTEN 0      511      0.0.0.0:1339  0.0.0.0:*
tcp LISTEN 0      511      0.0.0.0:1340  0.0.0.0:*
tcp LISTEN 0      128      0.0.0.0:26500 0.0.0.0:*
tcp LISTEN 0      128      0.0.0.0:50052 0.0.0.0:*
tcp LISTEN 0      128      0.0.0.0:8790  0.0.0.0:*
tcp LISTEN 0      511    127.0.0.1:46254 0.0.0.0:*
tcp LISTEN 0      32     127.0.0.1:5909  0.0.0.0:*
tcp LISTEN 0      32     127.0.0.1:5908  0.0.0.0:*
tcp LISTEN 0      32     127.0.0.1:5910  0.0.0.0:*
tcp LISTEN 0      32     127.0.0.1:5900  0.0.0.0:*
tcp LISTEN 0      32     127.0.0.1:5902  0.0.0.0:*
tcp LISTEN 0      5        0.0.0.0:2375  0.0.0.0:*
tcp LISTEN 0      511            *:13602       *:*
tcp LISTEN 0      511            *:13610       *:*
tcp LISTEN 0      511            *:13609       *:*
tcp LISTEN 0      511            *:13608       *:*
tcp LISTEN 0      511            *:14002       *:*
tcp LISTEN 0      511            *:14010       *:*
tcp LISTEN 0      511            *:14009       *:*
tcp LISTEN 0      511            *:14008       *:*
tcp LISTEN 0      511            *:1338        *:*
tcp LISTEN 0      511            *:1337        *:*
tcp LISTEN 0      32         [::1]:5908     [::]:*
tcp LISTEN 0      32         [::1]:5909     [::]:*
tcp LISTEN 0      32         [::1]:5910     [::]:*
tcp LISTEN 0      32         [::1]:5900     [::]:*
tcp LISTEN 0      32         [::1]:5902     [::]:*
```

### [INFO] Firewall status (information only)
UFW: not installed (or not in PATH).

This check never enables, disables, or changes firewall rules.

### [WARN] Passwordless sudo
Passwordless sudo indicators:
```
Current user can run passwordless sudo (`sudo -n true` succeeded).
```

### [INFO] Updates and unattended-upgrades
APT periodic stamps present under /var/lib/apt/periodic.

No readable unattended-upgrades auto config found.
Simulated pending upgrades from local cache (no refresh, no install): 0
This check never runs `apt update/upgrade/install`.

## Disclaimer

This is a **basic** audit for learning and portfolio use. It is **not** a penetration test,
compliance certification, or hardening tool. It never modifies the host: it only reads
configuration and writes this report file.
