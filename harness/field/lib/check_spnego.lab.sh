# shellcheck shell=bash
# check_spnego.lab.sh — the satomlin kit's lib/satomlin-common.sh (kit commit e9f3325): its helper block
# and check_spnego(), VERBATIM; only the four SSO constants carry the lab's values (field runner S2).
GREEN='\033[1;32m'; YELLOW='\033[1;33m'; RED='\033[1;31m'; NC='\033[0m'
print_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
# An empty argument is a real blank line, not five spaces (it was, in eight places).
print_info() { [ -n "${1:-}" ] && echo -e "     $1" || echo; }
SSO_AUTH_HOST="services.kerber.test"   # kit: auth.satomlin.com
SSO_REALM="kerber.test"                # kit: satomlin.com
SSO_PROBE_CLIENT="nextcloud"           # kit: nextcloud (unchanged)
SSO_PROBE_REDIRECT="https%3A%2F%2Fnextcloud.kerber.test%2Fapps%2Fuser_oidc%2Fcode"   # kit: https%3A%2F%2Fnextcloud.satomlin.com%2Fapps%2Fuser_oidc%2Fcode
check_spnego() {
  local url hdr code loc
  if ! klist -s 2>/dev/null; then
    print_info "no Kerberos TGT — SPNEGO handshake skipped"; return 0
  fi
  if ! getent hosts "$SSO_AUTH_HOST" >/dev/null 2>&1; then
    print_info "${SSO_AUTH_HOST} does not resolve (off-LAN?) — SPNEGO handshake skipped"; return 0
  fi
  url="https://${SSO_AUTH_HOST}/realms/${SSO_REALM}/protocol/openid-connect/auth"
  url="${url}?client_id=${SSO_PROBE_CLIENT}&response_type=code&scope=openid&redirect_uri=${SSO_PROBE_REDIRECT}"

  # 1. Is the challenge still offered?
  hdr="$(curl -sS --connect-timeout 5 --max-time 15 -D - -o /dev/null "$url" 2>&1)" \
    || { print_fail "cannot reach https://${SSO_AUTH_HOST}: $(printf '%s' "$hdr" | tail -1)"; return 1; }
  code="$(printf '%s' "$hdr" | awk '/^HTTP\//{c=$2} END{print c}')"
  case "$code" in
    401)
      printf '%s' "$hdr" | grep -qi '^www-authenticate: *negotiate' \
        || { print_fail "Keycloak answered 401 with no Negotiate challenge — the Kerberos execution is gone from its browser flow (runbook §5)"; return 1; } ;;
    400)
      print_warn "Keycloak rejected the probe client (HTTP 400) — SSO_PROBE_CLIENT / SSO_PROBE_REDIRECT in lib/satomlin-common.sh no longer match its registration; SPNEGO itself is UNTESTED"
      return 0 ;;
    *)
      print_fail "Keycloak did not challenge (HTTP ${code:-none}) — expected 401 + WWW-Authenticate: Negotiate"; return 1 ;;
  esac

  # 2. Does it accept OUR ticket? Only Keycloak's keytab can answer that.
  hdr="$(curl -sS --connect-timeout 5 --max-time 15 --negotiate -u : -o /dev/null \
               -w '%{http_code} %{redirect_url}' "$url" 2>/dev/null)" || hdr=""
  code="${hdr%% *}"; loc="${hdr#* }"
  if [[ "$code" == 302 && "$loc" == *code=* ]]; then
    print_ok "SPNEGO handshake: Keycloak accepted the ticket and issued an OIDC code"
    return 0
  fi
  if [[ "$code" == 401 ]]; then
    print_fail "Keycloak REFUSED the ticket (401 after Negotiate) — its keytab cannot decrypt HTTP/${SSO_AUTH_HOST}; kvno passes on exactly this fault (runbook §5 item 2)"
  else
    print_fail "SPNEGO handshake ended HTTP ${code:-none} — expected a 302 carrying an OIDC code"
  fi
  return 1
}
check_spnego; echo "check_spnego rc=$?"
