#!/usr/bin/env bash
# Simple bash test suite (no root, no bats required).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/helpers.sh
source "${ROOT}/lib/helpers.sh"

PASS=0
FAIL=0
assert_eq() {
  local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name (got='$got' want='$want')"
    FAIL=$((FAIL + 1))
  fi
}
assert_true() {
  local name="$1"
  shift
  if "$@"; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name"
    FAIL=$((FAIL + 1))
  fi
}
assert_false() {
  local name="$1"
  shift
  if ! "$@"; then
    echo "ok - $name"
    PASS=$((PASS + 1))
  else
    echo "not ok - $name (expected false)"
    FAIL=$((FAIL + 1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "# helpers: ssh_config_get"
cat > "$TMP/sshd_config" <<'CFG'
# comment
Port 22
PermitRootLogin yes
PasswordAuthentication no
# PermitRootLogin no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
CFG
got="$(ssh_config_get "$TMP/sshd_config" PermitRootLogin)"
assert_eq "PermitRootLogin last wins" "$got" "prohibit-password"
got="$(ssh_config_get "$TMP/sshd_config" PasswordAuthentication)"
assert_eq "PasswordAuthentication" "$got" "no"
got="$(ssh_config_get "$TMP/sshd_config" PermitEmptyPasswords)"
assert_eq "PermitEmptyPasswords" "$got" "no"
got="$(ssh_config_get "$TMP/missing" Port || true)"
assert_eq "missing file returns empty" "$got" ""

echo "# helpers: looks_mutating / refuse_mutating"
assert_true "apt install is mutating" looks_mutating "sudo apt install -y ufw"
assert_true "ufw enable is mutating" looks_mutating "ufw enable"
assert_true "chmod is mutating" looks_mutating "chmod 777 /etc/passwd"
assert_true "useradd is mutating" looks_mutating "useradd alice"
assert_true "sysctl -w is mutating" looks_mutating "sysctl -w net.ipv4.ip_forward=1"
assert_false "ss -tuln is not mutating" looks_mutating "ss -tuln"
assert_false "cat /etc/passwd is not mutating" looks_mutating "cat /etc/passwd"
assert_false "ufw status is not mutating" looks_mutating "ufw status"

set +e
refuse_mutating "apt-get install cowsay" >/dev/null 2>&1
rc=$?
set -e
assert_eq "refuse_mutating returns 2 for apt-get install" "$rc" "2"

set +e
refuse_mutating "ss -tuln" >/dev/null 2>&1
rc=$?
set -e
assert_eq "refuse_mutating allows ss" "$rc" "0"

echo "# audit.sh: help and report write"
assert_true "audit.sh is executable" test -x "${ROOT}/audit.sh"
"${ROOT}/audit.sh" --help >/dev/null

REPORT="$TMP/report.md"
"${ROOT}/audit.sh" --report "$REPORT" >/dev/null
assert_true "report file created" test -f "$REPORT"
assert_true "report has summary table" grep -q '| PASS |' "$REPORT"
assert_true "report says read-only" grep -qi 'read-only' "$REPORT"
assert_true "report has disclaimer" grep -qi 'not.*penetration test\|basic.*audit' "$REPORT"

echo "# audit.sh refuses system report paths"
set +e
"${ROOT}/audit.sh" --report /etc/evil-report.md >/dev/null 2>&1
rc=$?
set -e
assert_eq "refuse /etc report path" "$rc" "2"

echo "# audit.sh source has no mutating install/enable actions"
# The script must not contain these command forms as executable lines.
# Allow them only inside strings/comments for detection/tests documentation.
mut_hits="$(grep -nE '^\s*(sudo\s+)?(apt(-get)?\s+(install|remove|purge)|ufw\s+(enable|disable|allow)|chmod\s|chown\s|useradd\s)' "${ROOT}/audit.sh" || true)"
assert_eq "no mutating commands as statements in audit.sh" "$mut_hits" ""

echo "# static: helpers refuse_mutating exists"
assert_true "refuse_mutating function exists" bash -c "source '${ROOT}/lib/helpers.sh'; declare -F refuse_mutating >/dev/null"

echo
echo "Passed: $PASS  Failed: $FAIL"
if [[ "$FAIL" -ne 0 ]]; then
  exit 1
fi
