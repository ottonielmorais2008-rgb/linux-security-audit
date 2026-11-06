#!/usr/bin/env bash
# Shared helpers for linux-security-audit. Read-only helpers only.

# shellcheck shell=bash

audit_init_counters() {
  PASS_COUNT=0
  INFO_COUNT=0
  WARN_COUNT=0
  FAIL_COUNT=0
  SKIP_COUNT=0
  FINDINGS=()
}

# record_finding SEVERITY TITLE DETAIL
record_finding() {
  local severity="$1"
  local title="$2"
  local detail="$3"
  local tag
  case "$severity" in
    pass) tag="PASS"; PASS_COUNT=$((PASS_COUNT + 1)) ;;
    info) tag="INFO"; INFO_COUNT=$((INFO_COUNT + 1)) ;;
    warn) tag="WARN"; WARN_COUNT=$((WARN_COUNT + 1)) ;;
    fail) tag="FAIL"; FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    skip) tag="SKIP"; SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    *) tag="INFO"; INFO_COUNT=$((INFO_COUNT + 1)) ;;
  esac
  FINDINGS+=("### [${tag}] ${title}"$'\n'"${detail}"$'\n')
}

is_readable() {
  [[ -r "$1" ]]
}

is_file() {
  [[ -f "$1" ]]
}

is_root() {
  [[ "$(id -u)" -eq 0 ]]
}

cap_lines() {
  local max="${1:-20}"
  head -n "$max"
}

# Parse sshd_config-style key value (last non-comment match wins).
ssh_config_get() {
  local file="$1"
  local key="$2"
  local value=""
  local line k v
  [[ -r "$file" ]] || { printf ''; return 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    k="${line%%[[:space:]]*}"
    v="${line#"$k"}"
    v="${v#"${v%%[![:space:]]*}"}"
    if [[ "${k,,}" == "${key,,}" ]]; then
      value="$v"
    fi
  done < "$file"
  printf '%s' "$value"
}

# Return 0 if a string looks like a mutating shell action we must never run.
looks_mutating() {
  local cmd="$1"
  local lower
  lower="${cmd,,}"
  if [[ "$lower" =~ apt(-get)?[[:space:]]+(install|remove|purge) ]]; then return 0; fi
  if [[ "$lower" =~ ufw[[:space:]]+(enable|disable|allow|deny|reset|reload) ]]; then return 0; fi
  if [[ "$lower" =~ (^|[[:space:]])chmod[[:space:]] ]]; then return 0; fi
  if [[ "$lower" =~ (^|[[:space:]])chown[[:space:]] ]]; then return 0; fi
  if [[ "$lower" =~ (^|[[:space:]])chgrp[[:space:]] ]]; then return 0; fi
  if [[ "$lower" =~ (^|[[:space:]])(useradd|userdel|usermod|passwd|vipw|visudo)([[:space:]]|$) ]]; then return 0; fi
  if [[ "$lower" =~ systemctl[[:space:]]+(enable|disable|start|stop|restart|mask) ]]; then return 0; fi
  if [[ "$lower" =~ (^|[[:space:]])(rm|mkfs|dd|shred)[[:space:]] ]]; then return 0; fi
  if [[ "$lower" =~ iptables[[:space:]]+-[AIDP] ]]; then return 0; fi
  if [[ "$lower" =~ nft[[:space:]]+add ]]; then return 0; fi
  if [[ "$lower" =~ sysctl[[:space:]]+-w ]]; then return 0; fi
  return 1
}

refuse_mutating() {
  local cmd="$1"
  if looks_mutating "$cmd"; then
    echo "REFUSED (mutating): $cmd" >&2
    return 2
  fi
  echo "ALLOWED (not executed by guard alone): $cmd" >&2
  return 0
}
