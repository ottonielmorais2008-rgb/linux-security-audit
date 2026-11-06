# Linux Security Audit

A **read-only** Bash security audit for Ubuntu (and similar Debian-based hosts). It inspects common configuration risks, prints the findings, and writes a Markdown report. It **never** changes the system.

**Read it online:** https://ottonielmorais2008-rgb.github.io/linux-security-audit/

## What it checks

- Host identity (OS, kernel, whether the audit ran as root)
- Accounts with UID 0 besides `root`
- Empty password fields in `/etc/shadow` (skipped gracefully without root)
- Permissions on `/etc/shadow`
- SSH daemon settings: `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords` (including `sshd_config.d` drop-ins)
- SSH private key and `~/.ssh` directory modes
- World-writable files under sensitive paths (`/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/boot`)
- Unusual SUID/SGID binaries (compared to a small expected allow-list)
- Listening TCP/UDP ports (`ss` or `netstat`, if present)
- Firewall status as **information only** (UFW / iptables / nft — never enable, disable, or edit rules)
- Passwordless `sudo` (`NOPASSWD` in readable sudoers files; `sudo -n`)
- Unattended-upgrades / pending upgrades from the **local apt cache only** (never runs `apt update` or installs packages)

Checks that need root are skipped with a clear `SKIP` note instead of asking for `sudo`.

## Quick start

```bash
git clone https://github.com/ottonielmorais2008-rgb/linux-security-audit.git
cd linux-security-audit
bash audit.sh
```

Optional report path:

```bash
bash audit.sh --report /tmp/my-audit.md
```

## What this does not do

- It is **not** a penetration test, red-team toolkit, or compliance certification.
- It does **not** install packages, enable/disable UFW, change `chmod`/`chown`, create users, or edit system files.
- It does **not** require root. Without root, some checks are skipped and listed as `SKIP`.
- It only writes the Markdown report file you choose (default: `security-audit-report.md` next to the script). Writing under system paths such as `/etc` is refused.

See also the [sample report](docs/sample-report.md).

## Project layout

```
audit.sh                 # main read-only auditor
lib/helpers.sh           # parsers and a mutating-command guard
tests/run-tests.sh       # tests that run without root
docs/sample-report.md    # report from a real run
.github/workflows/ci.yml # GitHub Actions: tests + live audit on ubuntu-latest
```

## Tests and CI

```bash
bash tests/run-tests.sh
```

CI (GitHub Actions on `ubuntu-latest`, `actions/checkout@v5`, no secrets) runs the test suite and executes `audit.sh` on the runner to prove the audit works read-only.

## How it was tested

- Unit and safety tests via `tests/run-tests.sh` (SSH config parser, mutating-command refusal, report generation, refusal to write under `/etc`).
- Full audit run on the development host and again on the GitHub Actions `ubuntu-latest` runner; the published [sample report](docs/sample-report.md) comes from a real run (see the host/OS lines inside the report).
- No full virtual machine was used for this project.

## Risks and honesty

A basic audit can miss issues, mis-classify unusual but legitimate SUID binaries, or lack visibility without root. Treat findings as leads to investigate, not as proof that a host is secure. Never run untrusted scripts as root; this one is designed so you do not need to.

## Run locally

Clone the repository and run `bash audit.sh` as shown above. `localhost` is not used by this project; the public demo is the GitHub Pages site linked at the top.

## License

[MIT](LICENSE)
