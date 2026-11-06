# What this does not do

This page restates the safety boundary of **linux-security-audit**.

## Never modifies the host

The auditor does **not**:

- run `apt` / `apt-get` install, remove, or upgrade
- enable, disable, or edit UFW / iptables / nft rules
- change file modes or ownership (`chmod`, `chown`)
- create, delete, or modify user accounts
- write anywhere except the Markdown report path you pass with `--report`

## Not a pentest

Findings are a basic, automated checklist for learning and portfolio demonstration. They are not a substitute for a professional assessment, CIS benchmark run, or vulnerability scan.

## Privilege model

Run as a normal user. If a check cannot read a file (for example `/etc/shadow`), it records `SKIP` and continues. The tool will not prompt for or escalate to root.
