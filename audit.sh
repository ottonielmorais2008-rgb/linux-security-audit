#!/usr/bin/env bash
# linux-security-audit — read-only basic security audit for Ubuntu/Debian-like hosts.
# Never modifies the system. Writes only the Markdown report file you choose.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/helpers.sh
source "${SCRIPT_DIR}/lib/helpers.sh"

AUDIT_VERSION="1.0.0"
REPORT_PATH="${SCRIPT_DIR}/security-audit-report.md"
HOSTNAME_VAL="$(hostname 2>/dev/null || echo unknown)"
STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--report PATH] [--help]

Read-only Linux security audit. Prints findings and writes a Markdown report.
Never changes the host (no apt, ufw, chmod, useradd, etc.).

Options:
  --report PATH   Write the Markdown report here (default: ./security-audit-report.md
                  next to this script). Parent directory must already exist and be writable.
  --help          Show this help.

Exit codes:
  0  Report written (findings may still include FAIL/WARN).
  1  Usage / argument error.
  2  Could not write the report file.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report)
      [[ $# -ge 2 ]] || { echo "Missing value for --report" >&2; exit 1; }
      REPORT_PATH="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# --- Guard: refuse to treat report path as a system-critical file ---
case "$REPORT_PATH" in
  /etc/*|/boot/*|/usr/*|/bin/*|/sbin/*|/lib/*|/dev/*|/proc/*|/sys/*)
    echo "Refusing to write report under a system path: $REPORT_PATH" >&2
    exit 2
    ;;
esac

audit_init_counters

# -------------------- checks --------------------

check_identity() {
  local who uid os_pretty kernel
  who="$(id -un 2>/dev/null || echo unknown)"
  uid="$(id -u 2>/dev/null || echo unknown)"
  os_pretty="unknown"
  if [[ -r /etc/os-release ]]; then
    os_pretty="$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-unknown}")"
  fi
  kernel="$(uname -r 2>/dev/null || echo unknown)"
  record_finding info "Host identity" \
"Hostname: \`${HOSTNAME_VAL}\`
User: \`${who}\` (uid ${uid})
OS: ${os_pretty}
Kernel: ${kernel}
Audit version: ${AUDIT_VERSION}
Started (UTC): ${STARTED_AT}
Root privileges: $(is_root && echo yes || echo no)"
}

check_uid0_users() {
  local extras=""
  if ! is_readable /etc/passwd; then
    record_finding skip "UID 0 accounts" "Cannot read /etc/passwd."
    return
  fi
  extras="$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd || true)"
  if [[ -z "$extras" ]]; then
    record_finding pass "UID 0 accounts" "Only \`root\` has UID 0."
  else
    record_finding fail "UID 0 accounts" "Accounts other than root with UID 0:
\`\`\`
${extras}
\`\`\`"
  fi
}

check_empty_password_accounts() {
  if ! is_readable /etc/shadow; then
    record_finding skip "Empty password accounts" \
"Cannot read /etc/shadow (needs root). Skipped without elevating privileges."
    return
  fi
  local empty
  empty="$(awk -F: '($2 == "") { print $1 }' /etc/shadow 2>/dev/null || true)"
  if [[ -z "$empty" ]]; then
    record_finding pass "Empty password accounts" "No accounts with an empty password field in /etc/shadow."
  else
    record_finding fail "Empty password accounts" "Accounts with empty password field:
\`\`\`
${empty}
\`\`\`"
  fi
}

check_shadow_perms() {
  if [[ ! -e /etc/shadow ]]; then
    record_finding skip "Permissions on /etc/shadow" "/etc/shadow not found."
    return
  fi
  local perms owner group
  perms="$(stat -c '%a' /etc/shadow 2>/dev/null || echo unknown)"
  owner="$(stat -c '%U:%G' /etc/shadow 2>/dev/null || echo unknown)"
  # Expected on Ubuntu: 640 root:shadow or 600 root:root
  if [[ "$perms" == "640" || "$perms" == "600" ]]; then
    record_finding pass "Permissions on /etc/shadow" "Mode \`${perms}\`, owner \`${owner}\`."
  elif [[ "$perms" == "unknown" ]]; then
    record_finding skip "Permissions on /etc/shadow" "Could not stat /etc/shadow."
  else
    record_finding warn "Permissions on /etc/shadow" "Mode \`${perms}\`, owner \`${owner}\`. Expected 640 or 600."
  fi
}

check_ssh_config() {
  local conf="/etc/ssh/sshd_config"
  local drop_in_dir="/etc/ssh/sshd_config.d"
  if ! is_readable "$conf"; then
    record_finding skip "SSH daemon configuration" "Cannot read ${conf}."
    return
  fi

  local permit_root password_auth empty_pass challenge
  permit_root="$(ssh_config_get "$conf" PermitRootLogin)"
  password_auth="$(ssh_config_get "$conf" PasswordAuthentication)"
  empty_pass="$(ssh_config_get "$conf" PermitEmptyPasswords)"
  challenge="$(ssh_config_get "$conf" ChallengeResponseAuthentication)"

  # Merge drop-ins (later files override; we take last match across sorted files)
  if [[ -d "$drop_in_dir" ]]; then
    local f
    for f in "$drop_in_dir"/*.conf; do
      [[ -r "$f" ]] || continue
      local v
      v="$(ssh_config_get "$f" PermitRootLogin)"; [[ -n "$v" ]] && permit_root="$v"
      v="$(ssh_config_get "$f" PasswordAuthentication)"; [[ -n "$v" ]] && password_auth="$v"
      v="$(ssh_config_get "$f" PermitEmptyPasswords)"; [[ -n "$v" ]] && empty_pass="$v"
    done
  fi

  local detail
  detail="Effective values from readable sshd_config (+ drop-ins if present):
- PermitRootLogin: \`${permit_root:-<default/unset>}\`
- PasswordAuthentication: \`${password_auth:-<default/unset>}\`
- PermitEmptyPasswords: \`${empty_pass:-<default/unset>}\`
- ChallengeResponseAuthentication: \`${challenge:-<default/unset>}\`"

  local sev="pass"
  local notes=()

  case "${permit_root,,}" in
    yes|without-password|prohibit-password)
      sev="warn"
      notes+=("PermitRootLogin is '${permit_root}' — prefer \`no\` for locked-down hosts.")
      ;;
    no|"")
      ;;
  esac

  case "${password_auth,,}" in
    yes)
      if [[ "$sev" != "fail" ]]; then sev="warn"; fi
      notes+=("PasswordAuthentication is yes — key-only auth is stronger when keys are in use.")
      ;;
  esac

  case "${empty_pass,,}" in
    yes)
      sev="fail"
      notes+=("PermitEmptyPasswords is yes.")
      ;;
  esac

  if [[ ${#notes[@]} -gt 0 ]]; then
    detail+=$'\n\n'"Notes:"$'\n'
    local n
    for n in "${notes[@]}"; do
      detail+="- ${n}"$'\n'
    done
  else
    detail+=$'\n\nNo high-risk SSH settings detected from readable config.'
  fi

  record_finding "$sev" "SSH daemon configuration" "$detail"
}

check_ssh_key_perms() {
  local issues=()
  local path
  for path in /etc/ssh/ssh_host_*_key /root/.ssh/id_rsa /root/.ssh/id_ed25519; do
    [[ -e "$path" ]] || continue
    if ! is_readable "$path" && [[ ! -e "$path" ]]; then
      continue
    fi
    # Even if not readable, we may still stat mode
    local perms
    perms="$(stat -c '%a' "$path" 2>/dev/null || echo "")"
    [[ -n "$perms" ]] || continue
    if [[ "$path" == *"_key" && "$path" != *".pub" ]]; then
      if [[ "$perms" != "600" && "$perms" != "400" ]]; then
        issues+=("${path}: mode ${perms} (expected 600 or 400)")
      fi
    fi
  done

  # User SSH keys under /home (readable dirs only)
  local home
  for home in /home/*; do
    [[ -d "$home/.ssh" ]] || continue
    local f
    for f in "$home/.ssh"/id_rsa "$home/.ssh"/id_ed25519 "$home/.ssh"/id_ecdsa; do
      [[ -e "$f" ]] || continue
      local perms
      perms="$(stat -c '%a' "$f" 2>/dev/null || echo "")"
      [[ -n "$perms" ]] || continue
      if [[ "$perms" != "600" && "$perms" != "400" ]]; then
        issues+=("${f}: mode ${perms} (expected 600 or 400)")
      fi
    done
    if [[ -e "$home/.ssh/authorized_keys" ]]; then
      local aperms
      aperms="$(stat -c '%a' "$home/.ssh/authorized_keys" 2>/dev/null || echo "")"
      if [[ -n "$aperms" && "$aperms" != "600" && "$aperms" != "644" && "$aperms" != "640" ]]; then
        issues+=("${home}/.ssh/authorized_keys: mode ${aperms}")
      fi
    fi
  done

  if [[ ${#issues[@]} -eq 0 ]]; then
    record_finding pass "SSH private key permissions" \
"No overly open private key modes found among paths that could be inspected."
  else
    local body
    body="$(printf '%s\n' "${issues[@]}")"
    record_finding warn "SSH private key permissions" \
"Loose permissions detected:
\`\`\`
${body}
\`\`\`"
  fi
}

check_world_writable() {
  local paths=("/etc" "/bin" "/sbin" "/usr/bin" "/usr/sbin" "/boot")
  local found=()
  local p
  for p in "${paths[@]}"; do
    [[ -d "$p" ]] || continue
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      found+=("$f")
      if [[ ${#found[@]} -ge 30 ]]; then
        break 2
      fi
    done < <(find "$p" -xdev -type f -perm -0002 2>/dev/null | head -n 30)
  done

  if [[ ${#found[@]} -eq 0 ]]; then
    record_finding pass "World-writable files in sensitive paths" \
"No world-writable regular files found under /etc /bin /sbin /usr/bin /usr/sbin /boot (best-effort, non-root may miss some)."
  else
    local body
    body="$(printf '%s\n' "${found[@]}")"
    record_finding warn "World-writable files in sensitive paths" \
"Found (capped at 30):
\`\`\`
${body}
\`\`\`"
  fi
}

check_suid_sgid() {
  local unusual=()
  # Common expected SUID binaries (not exhaustive). Anything else is flagged as INFO/WARN.
  local expected='^(passwd|sudo|su|newgrp|chsh|chfn|mount|umount|ping|ping6|fusermount|fusermount3|pkexec|crontab|ssh-agent|ntfs-3g|unix_chkpwd|gpasswd)$'
  local f base
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    base="$(basename "$f")"
    if [[ ! "$base" =~ $expected ]]; then
      unusual+=("$f ($(stat -c '%a %U:%G' "$f" 2>/dev/null || echo '?'))")
    fi
    if [[ ${#unusual[@]} -ge 25 ]]; then
      break
    fi
  done < <(find /bin /sbin /usr/bin /usr/sbin -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -n 80)

  if [[ ${#unusual[@]} -eq 0 ]]; then
    record_finding info "Unusual SUID/SGID binaries" \
"No unusual SUID/SGID binaries beyond a small expected allow-list (or none readable). This is informational, not a full baseline."
  else
    local body
    body="$(printf '%s\n' "${unusual[@]}")"
    record_finding warn "Unusual SUID/SGID binaries" \
"Binaries with SUID/SGID not on the small expected allow-list (capped):
\`\`\`
${body}
\`\`\`
Review these; many are legitimate. This audit does not remove or change them."
  fi
}

check_listening_ports() {
  local out=""
  if command -v ss >/dev/null 2>&1; then
    out="$(ss -tulnH 2>/dev/null | cap_lines 40 || true)"
  elif command -v netstat >/dev/null 2>&1; then
    out="$(netstat -tuln 2>/dev/null | cap_lines 40 || true)"
  else
    record_finding skip "Listening ports" "Neither \`ss\` nor \`netstat\` is available."
    return
  fi
  if [[ -z "$out" ]]; then
    record_finding info "Listening ports" "No listening sockets reported (or insufficient permission)."
  else
    record_finding info "Listening ports" \
"Current listening sockets (read-only snapshot, capped):
\`\`\`
${out}
\`\`\`"
  fi
}

check_firewall_status() {
  local detail=""
  if command -v ufw >/dev/null 2>&1; then
    # ufw status is read-only
    detail+="UFW: $(ufw status 2>/dev/null | head -n 5 | tr '\n' ' ' || echo 'status unavailable')"
    detail+=$'\n'
  else
    detail+="UFW: not installed (or not in PATH)."$'\n'
  fi
  if command -v iptables >/dev/null 2>&1; then
    local rules
    rules="$(iptables -L -n 2>/dev/null | head -n 20 || true)"
    if [[ -n "$rules" ]]; then
      detail+=$'\n'"iptables filter table (first lines, read-only):
\`\`\`
${rules}
\`\`\`"
    else
      detail+=$'\n'"iptables: present but rules not readable without privileges (not elevating)."
    fi
  fi
  if command -v nft >/dev/null 2>&1; then
    detail+=$'\n'"nft: available ($(nft list ruleset 2>/dev/null | head -n 1 >/dev/null && echo 'ruleset readable' || echo 'ruleset not readable without privileges'))."
  fi
  record_finding info "Firewall status (information only)" \
"${detail}
This check never enables, disables, or changes firewall rules."
}

check_passwordless_sudo() {
  local hits=()
  local f
  if is_readable /etc/sudoers; then
    while IFS= read -r line; do
      [[ "$line" =~ ^[^#]*NOPASSWD ]] && hits+=("/etc/sudoers: $line")
    done < /etc/sudoers
  fi
  if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
      [[ -f "$f" && -r "$f" ]] || continue
      while IFS= read -r line; do
        [[ "$line" =~ ^[^#]*NOPASSWD ]] && hits+=("$f: $line")
      done < "$f"
    done
  fi

  # Also check if current user can sudo -n (does not change system; may prompt nothing)
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
      hits+=("Current user can run passwordless sudo (\`sudo -n true\` succeeded).")
    fi
  fi

  if [[ ${#hits[@]} -eq 0 ]]; then
    if ! is_readable /etc/sudoers; then
      record_finding skip "Passwordless sudo" \
"Cannot read /etc/sudoers or sudoers.d; current user has no passwordless sudo."
    else
      record_finding pass "Passwordless sudo" "No NOPASSWD entries found in readable sudoers files; current user cannot passwordless sudo."
    fi
  else
    local body
    body="$(printf '%s\n' "${hits[@]}")"
    record_finding warn "Passwordless sudo" \
"Passwordless sudo indicators:
\`\`\`
${body}
\`\`\`"
  fi
}

check_updates() {
  local detail=""
  if [[ -d /var/lib/apt/periodic ]]; then
    detail+="APT periodic stamps present under /var/lib/apt/periodic."$'\n'
  fi
  if [[ -r /var/lib/apt/periodic/update-success-stamp ]]; then
    detail+="Last successful apt update stamp: $(stat -c '%y' /var/lib/apt/periodic/update-success-stamp 2>/dev/null || echo unknown)"$'\n'
  fi
  if [[ -r /etc/apt/apt.conf.d/20auto-upgrades ]]; then
    detail+=$'\n'"unattended-upgrades / auto-upgrades config (/etc/apt/apt.conf.d/20auto-upgrades):
\`\`\`
$(cat /etc/apt/apt.conf.d/20auto-upgrades)
\`\`\`"
  elif [[ -r /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
    detail+=$'\n'"Found /etc/apt/apt.conf.d/50unattended-upgrades (readable)."
  else
    detail+=$'\n'"No readable unattended-upgrades auto config found."
  fi

  # Pending updates count without running apt update (read-only cache)
  if command -v apt-get >/dev/null 2>&1; then
    local pending
    pending="$(apt-get -s upgrade 2>/dev/null | awk '/^Inst / { c++ } END { print c+0 }' || echo "?")"
    detail+=$'\n'"Simulated pending upgrades from local cache (no refresh, no install): ${pending}"
  fi

  record_finding info "Updates and unattended-upgrades" \
"${detail}
This check never runs \`apt update/upgrade/install\`."
}

check_home_dot_ssh_world() {
  local bad=()
  local home
  for home in /home/* /root; do
    [[ -d "$home/.ssh" ]] || continue
    local mode
    mode="$(stat -c '%a' "$home/.ssh" 2>/dev/null || echo "")"
    [[ -n "$mode" ]] || continue
    # Reject if other-writable or world-readable excessively — .ssh should be 700
    if [[ "$mode" != "700" && "$mode" != "750" ]]; then
      bad+=("$home/.ssh mode ${mode} (prefer 700)")
    fi
  done
  if [[ ${#bad[@]} -eq 0 ]]; then
    record_finding pass "~/.ssh directory modes" "Inspected home .ssh directories look appropriately restricted (or none readable)."
  else
    record_finding warn "~/.ssh directory modes" "$(printf '%s\n' "${bad[@]}")"
  fi
}

# -------------------- run --------------------

check_identity
check_uid0_users
check_empty_password_accounts
check_shadow_perms
check_ssh_config
check_ssh_key_perms
check_home_dot_ssh_world
check_world_writable
check_suid_sgid
check_listening_ports
check_firewall_status
check_passwordless_sudo
check_updates

FINISHED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

{
  echo "# Linux security audit report"
  echo
  echo "- Host: \`${HOSTNAME_VAL}\`"
  echo "- Generated (UTC): ${FINISHED_AT}"
  echo "- Tool: linux-security-audit v${AUDIT_VERSION}"
  echo "- Mode: **read-only** (no system changes)"
  echo
  echo "## Summary"
  echo
  echo "| Severity | Count |"
  echo "|----------|------:|"
  echo "| PASS | ${PASS_COUNT} |"
  echo "| INFO | ${INFO_COUNT} |"
  echo "| WARN | ${WARN_COUNT} |"
  echo "| FAIL | ${FAIL_COUNT} |"
  echo "| SKIP | ${SKIP_COUNT} |"
  echo
  echo "## Findings"
  echo
  local_i=0
  for finding in "${FINDINGS[@]}"; do
    printf '%s\n' "$finding"
  done
  echo "## Disclaimer"
  echo
  echo "This is a **basic** audit for learning and portfolio use. It is **not** a penetration test,"
  echo "compliance certification, or hardening tool. It never modifies the host: it only reads"
  echo "configuration and writes this report file."
} > "${REPORT_PATH}.tmp" || { echo "Failed to write ${REPORT_PATH}.tmp" >&2; exit 2; }

mv "${REPORT_PATH}.tmp" "${REPORT_PATH}" || { echo "Failed to move report into place" >&2; exit 2; }

echo "Report written to: ${REPORT_PATH}"
echo "Summary: PASS=${PASS_COUNT} INFO=${INFO_COUNT} WARN=${WARN_COUNT} FAIL=${FAIL_COUNT} SKIP=${SKIP_COUNT}"
cat "${REPORT_PATH}"
