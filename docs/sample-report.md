# Linux security audit report

- Host: `runnervmwuk1x`
- Generated (UTC): 2026-11-06T10:21:42Z
- Tool: linux-security-audit v1.0.0
- Mode: **read-only** (no system changes)

## Summary

| Severity | Count |
|----------|------:|
| PASS | 6 |
| INFO | 4 |
| WARN | 2 |
| FAIL | 0 |
| SKIP | 1 |

## Findings

### [INFO] Host identity
Hostname: `runnervmwuk1x`
User: `runner` (uid 1001)
OS: Ubuntu 26.04.1 LTS
Kernel: 7.0.0-1019-azure
Audit version: 1.0.0
Started (UTC): 2026-11-06T10:21:40Z
Root privileges: no

### [PASS] UID 0 accounts
Only `root` has UID 0.

### [SKIP] Empty password accounts
Cannot read /etc/shadow (needs root). Skipped without elevating privileges.

### [PASS] Permissions on /etc/shadow
Mode `640`, owner `root:shadow`.

### [PASS] SSH daemon configuration
Effective values from readable sshd_config (+ drop-ins if present):
- PermitRootLogin: `<default/unset>`
- PasswordAuthentication: `no`
- PermitEmptyPasswords: `<default/unset>`
- ChallengeResponseAuthentication: `<default/unset>`

No high-risk SSH settings detected from readable config.

### [PASS] SSH private key permissions
No overly open private key modes found among paths that could be inspected.

### [PASS] ~/.ssh directory modes
Inspected home .ssh directories look appropriately restricted (or none readable).

### [PASS] World-writable files in sensitive paths
No world-writable regular files found under /etc /bin /sbin /usr/bin /usr/sbin /boot (best-effort, non-root may miss some).

### [WARN] Unusual SUID/SGID binaries
Binaries with SUID/SGID not on the small expected allow-list (capped):
```
/usr/bin/newuidmap (4755 root:root)
/usr/bin/sudo.ws (4755 root:root)
/usr/bin/expiry (2755 root:shadow)
/usr/bin/chage (2755 root:shadow)
/usr/bin/newgidmap (4755 root:root)
/usr/sbin/mount.cifs (4755 root:root)
/usr/sbin/pam_extrausers_chkpwd (2755 root:shadow)
```
Review these; many are legitimate. This audit does not remove or change them.

### [INFO] Listening ports
Current listening sockets (read-only snapshot, capped):
```
udp UNCONN 0      0          127.0.0.54:53  0.0.0.0:*
udp UNCONN 0      0       127.0.0.53%lo:53  0.0.0.0:*
udp UNCONN 0      0      10.1.1.68%eth0:68  0.0.0.0:*
udp UNCONN 0      0           127.0.0.1:323 0.0.0.0:*
udp UNCONN 0      0               [::1]:323    [::]:*
tcp LISTEN 0      4096       127.0.0.54:53  0.0.0.0:*
tcp LISTEN 0      4096          0.0.0.0:22  0.0.0.0:*
tcp LISTEN 0      4096    127.0.0.53%lo:53  0.0.0.0:*
tcp LISTEN 0      4096             [::]:22     [::]:*
```

### [INFO] Firewall status (information only)
UFW: status unavailable

iptables: present but rules not readable without privileges (not elevating).
nft: available (ruleset not readable without privileges).
This check never enables, disables, or changes firewall rules.

### [WARN] Passwordless sudo
Passwordless sudo indicators:
```
Current user can run passwordless sudo (`sudo -n true` succeeded).
```

### [INFO] Updates and unattended-upgrades
APT periodic stamps present under /var/lib/apt/periodic.
Last successful apt update stamp: 2026-11-01 21:35:15.970964632 +0000

No readable unattended-upgrades auto config found.
Simulated pending upgrades from local cache (no refresh, no install): 1
This check never runs `apt update/upgrade/install`.

## Disclaimer

This is a **basic** audit for learning and portfolio use. It is **not** a penetration test,
compliance certification, or hardening tool. It never modifies the host: it only reads
configuration and writes this report file.
