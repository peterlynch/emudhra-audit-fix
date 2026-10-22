#!/usr/bin/env bash
#
# emudhra-audit.sh - read-only audit of developer tools against the eMudhra
# intermediate CA compromise: https://emudhra.we-have-a-problem.com/
#
# Covers curl, git, Go, Python (incl. pip), Java, Node.js, Deno, Bun, rustup, uv, pixi, mise,
# Claude Code, Electron apps, Homebrew ca-certificates, system CA bundle files
# and OS CA packages. For each tool found it runs two checks:
#   1. Live probe   - the tool itself connects to hosts that chain to the
#                     compromised intermediates. A TLS certificate error means
#                     the tool is protected; a successful connection means it
#                     trusts the compromised chain (AFFECTED). A control host
#                     guards against proxy/network failures being misread.
#   2. Version check - compares the tool version with the fixed releases
#                     listed on the page (as of 2026-10-22).
# The probe is authoritative; the version check explains and backs it up.
#
# Affected items get remediation guidance (taken from the reference page).
# Guidance is only ever printed; this script never runs it.
#
# Audit only: nothing is installed, changed or removed. Small probe programs
# are written to a private temp directory, which is deleted on exit.
#
# Portable: bash 3.2+ (stock macOS) and Linux. No jq/python needed by the
# script itself.
#
# Exit status: 0 = nothing affected, 1 = at least one tool affected/likely
# affected, 2 = usage error.

VERSION_OF_SCRIPT=0.3.0

BAD_URLS="https://dv-g3b-emudhra.we-have-a-problem.com/ https://dv-g3b-aaa-emudhra.we-have-a-problem.com/"
CONTROL_URL="https://example.com/"

NO_NETWORK=0
VERBOSE=0
NO_GUIDE=0

usage() {
  cat <<EOF
Usage: ${0##*/} [--no-network] [--no-guidance] [--verbose] [-h|--help]

Read-only audit of developer tools (curl, git, Go, Python, Java, Node.js, Deno, Bun,
rustup, uv, pixi, mise, Claude Code, Electron apps, Homebrew and OS CA bundles)
against the eMudhra intermediate CA compromise. Prints remediation guidance for
anything affected; it never changes the system.

  --no-network    skip live TLS probes; version checks only
  --no-guidance   do not print remediation guidance
  --verbose       print the probe commands that are run, and raw TLS errors
  -h, --help      show this help
EOF
}

for arg in "$@"; do
  case $arg in
    --no-network)  NO_NETWORK=1 ;;
    --no-guidance) NO_GUIDE=1 ;;
    --verbose)     VERBOSE=1 ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t emudhra)
if [ -z "$TMP" ] || [ ! -d "$TMP" ]; then
  echo "Could not create a temporary directory" >&2
  exit 2
fi
trap 'rm -rf "$TMP"' EXIT

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_RED=; C_GRN=; C_YEL=; C_DIM=; C_BLD=; C_OFF=
fi

N_BAD=0; N_OK=0; N_UNK=0
SEEN=$'\n'
FIXV=            # fixed version(s) for the tool being checked (set by check_*_version)
FIX=             # guidance lines for the item about to be reported (see fix())
GUIDE=           # accumulated guidance for affected items
ADVISE=          # accumulated guidance for items that are protected but behind
FIXSYS=0; FIXPIP=0       # set by fix_* when an item's guidance points at a shared block
NEED_SYS=0; NEED_PIPMAC=0  # shared guidance blocks to print (only if an affected item needs them)
BREW_PREFIX=
PYBIN=
PROBE_RES=
NODE_SYSCA_RES=

# ---------------------------------------------------------------- helpers

log_cmd() { [ "$VERBOSE" -eq 1 ] && printf '%s  $ %s%s\n' "$C_DIM" "$*" "$C_OFF"; return 0; }

# Under --verbose, show (then clear) any raw errors a probe wrote to $TMP/err.
show_err() {
  [ "$VERBOSE" -eq 1 ] && [ -s "$TMP/err" ] && sed 's/^/  /' "$TMP/err"
  : > "$TMP/err"
  return 0
}

# run_to SECS CMD... : run a command, killing it after SECS seconds (no coreutils timeout needed).
run_to() {
  local secs=$1 pid wd rc
  shift
  "$@" &
  pid=$!
  ( sleep "$secs"; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  wd=$!
  wait "$pid" 2>/dev/null
  rc=$?
  kill "$wd" 2>/dev/null
  wait "$wd" 2>/dev/null
  return $rc
}

ENV_CA_VARS="SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE REQUESTS_CA_BUNDLE PIP_CERT GIT_SSL_CAINFO GIT_SSL_CAPATH NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA"

# env_notes VAR... : "note:" lines for any of the named environment variables that are set.
env_notes() {
  local v val out=
  for v in "$@"; do
    val=${!v}
    [ -n "$val" ] && out="${out:+$out
}    note:    $v=$val"
  done
  printf '%s' "$out"
}

audit_env() {
  section "CA-related environment"
  local v val any=0
  for v in $ENV_CA_VARS; do
    val=${!v}
    if [ -n "$val" ]; then printf '  %s=%s\n' "$v" "$val"; any=1; fi
  done
  for v in NODE_OPTIONS JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS; do
    val=${!v}
    case $val in
      *system-ca*|*extra-ca*|*cert*|*tls*|*trustStore*|*truststore*) printf '  %s=%s\n' "$v" "$val"; any=1 ;;
    esac
  done
  [ "$any" -eq 0 ] && echo "  no CA-related variables set"
  [ -n "${GIT_SSL_NO_VERIFY:-}" ]          && printf '  %sWARNING%s GIT_SSL_NO_VERIFY is set: git skips certificate checks, so git will report AFFECTED.\n' "$C_RED" "$C_OFF"
  [ "${NODE_TLS_REJECT_UNAUTHORIZED:-}" = 0 ] && printf '  %sWARNING%s NODE_TLS_REJECT_UNAUTHORIZED=0: Node skips certificate checks, so Node will report AFFECTED.\n' "$C_RED" "$C_OFF"
  [ "${PYTHONHTTPSVERIFY:-}" = 0 ]         && printf '  %sWARNING%s PYTHONHTTPSVERIFY=0 is set (ignored by the isolated probes, but affects your own Python scripts).\n' "$C_RED" "$C_OFF"
  echo "  The probes below inherit this environment, so each result is how the tool behaves in this shell."
  echo
  return 0
}

# Portable realpath for a file (follows symlinks, no readlink -f needed).
resolve() {
  local p=$1 t d n=0
  while [ -L "$p" ] && [ "$n" -lt 20 ]; do
    t=$(readlink "$p")
    case $t in /*) p=$t ;; *) p=$(dirname "$p")/$t ;; esac
    n=$((n + 1))
  done
  d=$(cd -P "$(dirname "$p")" 2>/dev/null && pwd) || { echo "$p"; return; }
  echo "$d/$(basename "$p")"
}

# Returns 1 if key was already seen, else records it.
first_time() {
  case $SEEN in *$'\n'"$1"$'\n'*) return 1 ;; esac
  SEEN="$SEEN$1"$'\n'
  return 0
}

# ver_ge A B : succeeds if dotted-numeric A >= B (missing parts = 0).
ver_ge() {
  local IFS=. a b i x y max
  a=($1); b=($2)
  max=${#a[@]}; [ "${#b[@]}" -gt "$max" ] && max=${#b[@]}
  i=0
  while [ "$i" -lt "$max" ]; do
    x=${a[$i]:-0}; y=${b[$i]:-0}
    x=${x%%[!0-9]*}; y=${y%%[!0-9]*}
    [ -z "$x" ] && x=0
    [ -z "$y" ] && y=0
    [ "$x" -gt "$y" ] && return 0
    [ "$x" -lt "$y" ] && return 1
    i=$((i + 1))
  done
  return 0
}

# judge: reads "<result> <url>" lines (result = ok|certerr|err) and prints
# trusted | rejected | inconclusive:<why>
judge() {
  local r u ctl= trusted=0 rejected=0 other=0
  while read -r r u; do
    if [ "$u" = "$CONTROL_URL" ]; then ctl=$r; continue; fi
    case $r in
      ok)      trusted=$((trusted + 1)) ;;
      certerr) rejected=$((rejected + 1)) ;;
      *)       other=$((other + 1)) ;;
    esac
  done
  if [ -z "$ctl" ]; then echo "inconclusive:probe produced no result"; return; fi
  if [ "$ctl" = certerr ]; then echo "inconclusive:control host ($CONTROL_URL) also failed certificate checks - this tool has no usable CA bundle, or a proxy intercepts TLS"; return; fi
  if [ "$ctl" != ok ]; then echo "inconclusive:control host ($CONTROL_URL) unreachable - network or proxy problem"; return; fi
  if [ "$trusted" -gt 0 ]; then echo trusted; return; fi
  if [ "$rejected" -gt 0 ] && [ "$other" -eq 0 ]; then echo rejected; return; fi
  echo "inconclusive:test hosts unreachable or failed for a non-certificate reason"
}

# combine_probe V... : overall verdict from several probe verdicts (empty ones ignored).
# Any trusted wins; otherwise any rejected; otherwise the first non-skipped verdict.
combine_probe() {
  local v first= rej=0
  for v in "$@"; do
    case $v in
      "")       ;;
      trusted*) echo trusted; return ;;
      rejected) rej=1 ;;
      skipped*) ;;
      *)        [ -z "$first" ] && first=$v ;;
    esac
  done
  if [ "$rej" -eq 1 ]; then echo rejected; return; fi
  echo "${first:-$1}"
}

describe_probe() {
  case $1 in
    trusted)       echo "AFFECTED - connected to a host using the compromised chain" ;;
    rejected)      echo "protected - certificate rejected" ;;
    skipped*)      echo "skipped (${1#skipped:})" ;;
    inconclusive*) echo "inconclusive - ${1#inconclusive:}" ;;
    *)             echo "$1" ;;
  esac
}

describe_version() {
  case $1 in
    ok)      echo "up to date" ;;
    behind)  echo "BEHIND" ;;
    nofix)   echo "NO FIX for this release line" ;;
    na)      echo "n/a" ;;
    *)       echo "could not determine" ;;
  esac
}

# report TOOL PATH VERSION VCHECK VNOTE PROBE [EXTRA-LINES]
report() {
  local tool=$1 path=$2 ver=$3 vc=$4 vn=$5 pr=$6 extra=${7:-} status col vtxt fx
  case $pr in
    trusted)  status=AFFECTED ;;
    rejected) status=OK ;;
    *) case $vc in
         behind|nofix) status=LIKELY-AFFECTED ;;
         ok)           status=LIKELY-OK ;;
         *)            status=UNKNOWN ;;
       esac ;;
  esac
  fx=$FIX
  [ -z "$fx" ] && fx="      (no specific guidance - see https://emudhra.we-have-a-problem.com/)"$'\n'
  case $status in
    AFFECTED|LIKELY-AFFECTED)
      N_BAD=$((N_BAD + 1)); col=$C_RED
      [ "$FIXSYS" = 1 ] && NEED_SYS=1
      [ "$FIXPIP" = 1 ] && NEED_PIPMAC=1
      GUIDE="${GUIDE}  - ${tool} ${ver}"$'\n'"    ${path}"$'\n'"${fx}"$'\n' ;;
    OK|LIKELY-OK)
      N_OK=$((N_OK + 1)); col=$C_GRN
      if [ "$status" = OK ] && { [ "$vc" = behind ] || [ "$vc" = nofix ]; }; then
        ADVISE="${ADVISE}  - ${tool} ${ver}"$'\n'"    ${path}"$'\n'"${fx}"$'\n'
      fi ;;
    *)
      N_UNK=$((N_UNK + 1)); col=$C_YEL ;;
  esac
  FIX=; FIXSYS=0; FIXPIP=0
  vtxt=$(describe_version "$vc")
  [ -n "$vn" ] && vtxt="$vtxt - $vn"
  printf '%s%s[%s]%s %s %s\n' "$C_BLD" "$col" "$status" "$C_OFF" "$tool" "$ver"
  printf '    path:    %s\n' "$path"
  printf '    version: %s\n' "$vtxt"
  printf '    probe:   %s\n' "$(describe_probe "$pr")"
  [ -n "$extra" ] && printf '%s\n' "$extra"
  echo
}

section() { printf '%s== %s ==%s\n' "$C_BLD" "$1" "$C_OFF"; }

# ----------------------------------------------------------- probe programs

cat > "$TMP/py_probe.py" <<'EOF'
import sys, ssl

def meta(name):
    try:
        import importlib.metadata as m
        return m.version(name)
    except Exception:
        return ""

mode = sys.argv[1]
if mode == "info":
    print("pyver=%d.%d.%d" % sys.version_info[:3])
    print("certifi=" + meta("certifi"))
    print("pip=" + meta("pip"))
    print("cafile=" + str(ssl.get_default_verify_paths().cafile))
    print("openssl=" + ssl.OPENSSL_VERSION)
else:
    import urllib.request, urllib.error
    urls = sys.argv[2:]
    if mode == "certifi":
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    elif mode == "cafile":
        ctx = ssl.create_default_context(cafile=sys.argv[2])
        urls = sys.argv[3:]
    else:
        ctx = ssl.create_default_context()
    for u in urls:
        try:
            urllib.request.urlopen(u, timeout=10, context=ctx).read(1)
            r = "ok"
        except urllib.error.HTTPError:
            r = "ok"
        except Exception as e:
            r = "certerr" if "CERTIFICATE_VERIFY_FAILED" in str(e) else "err"
            sys.stderr.write("    error: %s\n" % e)
        print(r, u)
EOF

mkdir -p "$TMP/go"
cat > "$TMP/go/probe.go" <<'EOF'
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	c := &http.Client{Timeout: 10 * time.Second}
	for _, u := range os.Args[1:] {
		r := "ok"
		resp, err := c.Get(u)
		if err != nil {
			if strings.Contains(err.Error(), "x509:") {
				r = "certerr"
			} else {
				r = "err"
			}
		} else {
			resp.Body.Close()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "    error:", err)
		}
		fmt.Println(r, u)
	}
}
EOF

mkdir -p "$TMP/java-src" "$TMP/java-cls"
cat > "$TMP/java-src/EmudhraProbe.java" <<'EOF'
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;

public class EmudhraProbe {
    public static void main(String[] args) {
        for (String u : args) {
            String r;
            try {
                HttpsURLConnection c = (HttpsURLConnection) new URL(u).openConnection();
                c.setConnectTimeout(10000);
                c.setReadTimeout(10000);
                c.getResponseCode();
                r = "ok";
            } catch (SSLException e) {
                boolean cert = false;
                for (Throwable t = e; t != null; t = t.getCause()) {
                    if (t instanceof java.security.cert.CertificateException
                            || t instanceof java.security.cert.CertPathValidatorException
                            || String.valueOf(t.getMessage()).contains("PKIX")) {
                        cert = true;
                    }
                }
                r = cert ? "certerr" : "err";
            } catch (Exception e) {
                r = "err";
            }
            System.out.println(r + " " + u);
        }
    }
}
EOF

# ------------------------------------------------------------------- curl

# curl_probe_all CURL : prints "<result> <url>" for the control and test hosts.
# Exit codes: 35/51/58/59/60/77/82/83/90/91 are TLS/certificate failures.
curl_probe_all() {
  local u rc
  for u in $CONTROL_URL $BAD_URLS; do
    "$1" -q -sS -o /dev/null --max-time 10 "$u" >/dev/null 2>&1
    rc=$?
    case $rc in
      0)                             echo "ok $u" ;;
      35|51|58|59|60|77|82|83|90|91) echo "certerr $u" ;;
      *)                             echo "err $u" ;;
    esac
  done
}

audit_curl() {
  section "curl"
  local found=0 c key vline ver tls out res env_note
  local cands
  cands=$(
    { type -ap curl 2>/dev/null
      for c in /usr/bin/curl /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl \
               /home/linuxbrew/.linuxbrew/opt/curl/bin/curl; do
        [ -x "$c" ] && echo "$c"
      done; } | awk '!s[$0]++'
  )
  for c in $cands; do
    [ -x "$c" ] || continue
    key="curl:$(resolve "$c")"
    first_time "$key" || continue
    found=1
    vline=$("$c" --version 2>/dev/null | head -1)
    ver=$(printf '%s\n' "$vline" | awk '{print $2}')
    tls=$(printf '%s\n' "$vline" | sed -n 's/.*libcurl\/[^ ]* (\([^)]*\)).*/\1/p')
    [ -z "$tls" ] && tls=$(printf '%s\n' "$vline" | sed -n 's/.*libcurl\/[^ ]* \([^ ]*\).*/\1/p')

    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"
    else
      log_cmd "$c -q -sS --max-time 10 -o /dev/null <url>   (control + test hosts)"
      out=$(curl_probe_all "$c")
      res=$(printf '%s\n' "$out" | judge)
    fi
    env_note=$(env_notes CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR)
    [ "${res%%:*}" = trusted ] && fix_curl "$c"
    report "curl" "$c" "${ver:-?} (TLS: ${tls:-?})" na "no fixed curl version; depends on the CA bundle/OS trust store in use" "$res" "$env_note"
  done
  [ "$found" -eq 0 ] && { echo "  not found"; echo; }
}

# --------------------------------------------------------------------- Go

# Sets VC / VN for a Go version like 1.26.4
check_go_version() {
  local v=$1 fix
  v=${v%%[!0-9.]*}
  if [ -z "$v" ]; then VC=unknown; VN=; return; fi
  FIXV=
  case $v in
    1.27|1.27.*) fix=1.27.3 ;;
    1.26|1.26.*) fix=1.26.10 ;;
    *)
      if ver_ge "$v" 1.28; then VC=ok; VN="newer than the fixed lines (1.26.10, 1.27.3)"
      else VC=nofix; VN="fixes only published for 1.26.10 and 1.27.3"; FIXV="1.26.10 or 1.27.3"; fi
      return ;;
  esac
  FIXV=$fix
  if ver_ge "$v" "$fix"; then VC=ok; VN="fixed in $fix"; else VC=behind; VN="fixed in $fix"; fi
}

audit_go() {
  section "Go"
  local found=0 g key gv v res out d
  local cands
  cands=$(
    { type -ap go 2>/dev/null
      for d in /usr/local/go/bin/go /opt/homebrew/opt/go/libexec/bin/go /usr/local/opt/go/libexec/bin/go \
               "$HOME"/sdk/go*/bin/go "$HOME"/go/pkg/mod/golang.org/toolchain@*/bin/go \
               "$HOME"/.asdf/installs/golang/*/go/bin/go "$HOME"/.local/share/mise/installs/go/*/bin/go; do
        [ -x "$d" ] && echo "$d"
      done; } | awk '!s[$0]++'
  )
  for g in $cands; do
    [ -x "$g" ] || continue
    key="go:$(resolve "$g")"
    first_time "$key" || continue
    found=1
    gv=$(GOTOOLCHAIN=local "$g" version 2>/dev/null | awk '{print $3}')
    v=${gv#go}
    check_go_version "$v"
    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"
    else
      log_cmd "(cd <tmp> && GOTOOLCHAIN=local $g run probe.go <urls>)"
      out=$(cd "$TMP/go" && GOTOOLCHAIN=local GOFLAGS= GOWORK=off "$g" run probe.go $CONTROL_URL $BAD_URLS 2>"$TMP/err")
      show_err
      res=$(printf '%s\n' "$out" | judge)
    fi
    fix_go "$g" "$res"
    report "Go" "$g" "${gv:-?}" "$VC" "$VN" "$res"
  done
  [ "$found" -eq 0 ] && { echo "  not found"; echo; }
}

# ----------------------------------------------------------------- Python

python_candidates() {
  local IFS=: d p base
  for d in $PATH /opt/homebrew/bin /usr/local/bin "$HOME"/.pyenv/versions/*/bin \
           /Library/Frameworks/Python.framework/Versions/*/bin \
           "$HOME"/.asdf/installs/python/*/bin "$HOME"/.local/share/mise/installs/python/*/bin; do
    [ -d "$d" ] || continue
    for p in "$d"/python*; do
      base=${p##*/}
      case $base in
        python|python[0-9]|python[0-9].[0-9]|python[0-9].[0-9][0-9]) [ -x "$p" ] && echo "$p" ;;
      esac
    done
  done
}

# pip_probe_all PYTHON : pip's own TLS behaviour. Asks each host's /simple/ index for a package
# that does not exist; any HTTP answer (even 404) means the TLS handshake was accepted.
pip_probe_all() {
  local u rc out
  for u in $CONTROL_URL $BAD_URLS; do
    rm -rf "$TMP/pipdl"
    run_to 40 "$1" -I -m pip download --no-deps --no-input --disable-pip-version-check \
      --retries 0 --timeout 10 -d "$TMP/pipdl" --index-url "${u}simple/" emudhra-probe-does-not-exist \
      >"$TMP/pipout" 2>&1 </dev/null
    rc=$?
    if grep -qi -E 'CERTIFICATE_VERIFY_FAILED|certificate verify failed|SSLCertVerificationError|problem confirming the ssl certificate|SSLError' "$TMP/pipout"; then
      out=certerr
    elif [ "$rc" -ge 128 ] || grep -qi -E 'NewConnectionError|Name or service not known|nodename nor servname|Temporary failure|ConnectTimeout|ReadTimeout|ProxyError|Connection refused|timed out|No module named' "$TMP/pipout"; then
      out=err
    else
      out=ok
    fi
    if [ "$out" != ok ]; then
      { grep -i -m1 -E 'CERTIFICATE_VERIFY_FAILED|certificate verify failed|SSLError|ssl certificate|NewConnection|timed out|ProxyError|No module' "$TMP/pipout" || tail -1 "$TMP/pipout"; } |
        cut -c1-220 | sed 's/^/    error: /' >> "$TMP/err"
    fi
    echo "$out $u"
  done
}

audit_python() {
  section "Python"
  local found=0 p key info pv cf pip cafile ossl res1 res2 res3 res vc vn out extra envn
  local cands
  cands=$(python_candidates | awk '!s[$0]++')
  for p in $cands; do
    # macOS /usr/bin/python3 is a stub that prompts to install the Command Line Tools.
    if [ "$p" = /usr/bin/python3 ] && [ "$(uname)" = Darwin ] && ! xcode-select -p >/dev/null 2>&1; then
      continue
    fi
    key="python:$(resolve "$p")"
    first_time "$key" || continue
    found=1
    info=$("$p" -I "$TMP/py_probe.py" info 2>/dev/null)
    pv=$(printf '%s\n' "$info" | sed -n 's/^pyver=//p')
    if [ -z "$pv" ]; then
      report "Python" "$p" "?" unknown "" "inconclusive:interpreter could not run the probe (Python 3.8+ needed)"
      continue
    fi
    [ -z "$PYBIN" ] && PYBIN=$p
    cf=$(printf '%s\n' "$info" | sed -n 's/^certifi=//p')
    pip=$(printf '%s\n' "$info" | sed -n 's/^pip=//p')
    cafile=$(printf '%s\n' "$info" | sed -n 's/^cafile=//p')
    ossl=$(printf '%s\n' "$info" | sed -n 's/^openssl=//p')

    # Version check: certifi >= 2026.10.19, pip >= 26.2.2 (CPython itself has no listed fix;
    # it uses the OS/OpenSSL trust store, which the probe covers).
    vc=na; vn=
    if [ -n "$cf" ]; then
      if ver_ge "$cf" 2026.10.19; then vn="certifi $cf ok"; vc=ok; else vn="certifi $cf < 2026.10.19"; vc=behind; fi
    fi
    if [ -n "$pip" ]; then
      if ver_ge "$pip" 26.2.2; then
        vn="${vn:+$vn; }pip $pip ok"; [ "$vc" = na ] && vc=ok
      else
        vn="${vn:+$vn; }pip $pip < 26.2.2"; vc=behind
      fi
    fi

    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"; res1=$res; res2=; res3=
    else
      log_cmd "$p -I <tmp>/py_probe.py default <urls>"
      out=$("$p" -I "$TMP/py_probe.py" default $CONTROL_URL $BAD_URLS 2>"$TMP/err")
      show_err
      res1=$(printf '%s\n' "$out" | judge)
      res2=
      if [ -n "$cf" ]; then
        log_cmd "$p -I <tmp>/py_probe.py certifi <urls>"
        out=$("$p" -I "$TMP/py_probe.py" certifi $CONTROL_URL $BAD_URLS 2>"$TMP/err")
        show_err
        res2=$(printf '%s\n' "$out" | judge)
      fi
      if "$p" -I -m pip --version >/dev/null 2>&1 </dev/null; then
        log_cmd "$p -I -m pip download --no-deps --index-url <host>/simple/ emudhra-probe-does-not-exist"
        out=$(pip_probe_all "$p")
        show_err
        res3=$(printf '%s\n' "$out" | judge)
      else
        res3="skipped:pip is not installed for this interpreter"
      fi
      res=$(combine_probe "$res1" "$res2" "$res3")
    fi
    extra="    detail:  default trust store: $(describe_probe "$res1")"
    [ -n "$res2" ] && extra="$extra
             certifi bundle:      $(describe_probe "$res2")"
    [ -n "$res3" ] && extra="$extra
             pip download:        $(describe_probe "$res3")"
    extra="$extra
             OpenSSL cafile:      ${cafile:-none}  (${ossl:-?})"
    envn=$(env_notes SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE PIP_CERT)
    [ -n "$envn" ] && extra="$extra
$envn"
    fix_python "$p" "$cafile" "$res1" "$res2" "$vc" "$res3"
    report "Python" "$p" "$pv" "$vc" "$vn" "$res" "$extra"
  done
  [ "$found" -eq 0 ] && { echo "  not found"; echo; }
}

# ------------------------------------------------------------------- Java

# Sets VC / VN for a java.version string (e.g. 11.0.32, 1.8.0_504, 21.0.12+1)
check_java_version() {
  local v=$1 major fix upd
  case $v in
    1.8.0_*)
      upd=${v#1.8.0_}; upd=${upd%%[!0-9]*}
      if [ -n "$upd" ] && [ "$upd" -ge 511 ]; then VC=ok; else VC=behind; fi
      VN="fixed in 8u511"; FIXV=8u511
      return ;;
  esac
  FIXV=
  major=${v%%[!0-9]*}
  v=${v%%[!0-9.]*}
  case $major in
    11) fix=11.0.33 ;;
    17) fix=17.0.21 ;;
    21) fix=21.0.13 ;;
    25) fix=25.0.5 ;;
    27) fix=27.0.1 ;;
    "") VC=unknown; VN=; return ;;
    *)
      if [ "$major" -gt 27 ]; then VC=ok; VN="newer than the fixed lines"
      else VC=nofix; VN="fixes only published for 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1"
        FIXV="a fixed release of a supported line (8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1)"; fi
      return ;;
  esac
  FIXV=$fix
  # The page lists e.g. 11.0.33.0.2; compare on the first three components.
  if ver_ge "$v" "$fix"; then VC=ok; else VC=behind; fi
  VN="fixed in $fix (page lists $fix.0.2)"
}

java_candidates() {
  local p d
  [ -n "${JAVA_HOME:-}" ] && echo "$JAVA_HOME"
  p=$(command -v java 2>/dev/null)
  [ -n "$p" ] && dirname "$(dirname "$(resolve "$p")")"
  [ -x /usr/libexec/java_home ] && /usr/libexec/java_home -V 2>&1 | sed -n 's/.*[[:space:]]\(\/.*\)$/\1/p'
  for d in /Library/Java/JavaVirtualMachines/*/Contents/Home \
           "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home \
           /usr/lib/jvm/* /usr/java/* /opt/java/* /opt/jdk* \
           "$HOME"/.sdkman/candidates/java/* "$HOME"/.asdf/installs/java/* \
           "$HOME"/.local/share/mise/installs/java/* "$HOME"/.jdks/* \
           /opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
           /usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
           /home/linuxbrew/.linuxbrew/opt/openjdk*/libexec; do
    [ -d "$d" ] && echo "$d"
  done
}

audit_java() {
  section "Java (JRE/JDK)"
  local homes="" h hp key found=0 jv vendor res out j
  for h in $(java_candidates | awk '!s[$0]++'); do
    [ -x "$h/bin/java" ] || continue
    hp=$(cd -P "$h" 2>/dev/null && pwd) || continue
    first_time "java:$hp" || continue
    homes="$homes$hp"$'\n'
  done

  # Compile the probe once with any javac (targeting Java 8 so every JRE can run it).
  local compiled=0 jc
  if [ "$NO_NETWORK" -eq 0 ]; then
    for h in $homes; do
      jc="$h/bin/javac"
      [ -x "$jc" ] || continue
      if "$jc" --release 8 -d "$TMP/java-cls" "$TMP/java-src/EmudhraProbe.java" >/dev/null 2>&1 ||
         "$jc" -source 8 -target 8 -d "$TMP/java-cls" "$TMP/java-src/EmudhraProbe.java" >/dev/null 2>&1; then
        compiled=1; log_cmd "$jc --release 8 -d <tmp> EmudhraProbe.java"; break
      fi
    done
  fi

  for h in $homes; do
    j="$h/bin/java"
    jv=$("$j" -version 2>&1 | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)
    if [ -z "$jv" ]; then continue; fi
    found=1
    vendor=
    [ -r "$h/release" ] && vendor=$(sed -n 's/^IMPLEMENTOR="\(.*\)"/\1/p' "$h/release" | head -1)
    check_java_version "$jv"
    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"
    elif [ "$compiled" -eq 0 ]; then
      res="skipped:no javac found to build the probe - version check only"
    else
      log_cmd "$j -cp <tmp> EmudhraProbe <urls>"
      out=$("$j" -cp "$TMP/java-cls" EmudhraProbe $CONTROL_URL $BAD_URLS 2>/dev/null)
      res=$(printf '%s\n' "$out" | judge)
    fi
    fix_java "$h" "$res"
    report "Java" "$h" "$jv${vendor:+ ($vendor)}" "$VC" "$VN" "$res"
  done
  [ "$found" -eq 0 ] && { echo "  not found"; echo; }
}

# ------------------------------------------------- guidance helpers (print only)

# fix LINE : add a guidance line for the item about to be reported.
fix() { FIX="${FIX}      $1"$'\n'; }

# where_from PATH : how a tool was probably installed, to tailor upgrade advice.
where_from() {
  case $1 in
    */.nvm/*)      echo nvm ;;
    */.volta/*)    echo volta ;;
    */fnm/*)       echo fnm ;;
    */.asdf/*)     echo asdf ;;
    */mise/*)      echo mise ;;
    */.sdkman/*)   echo sdkman ;;
    */.pyenv/*)    echo pyenv ;;
    */.cargo/*)    echo cargo ;;
    */Cellar/*|/opt/homebrew/*|/usr/local/opt/*|*/.linuxbrew/*) echo brew ;;
    /usr/local/go/*) echo golang ;;
    /Applications/*|*/Applications/*) echo app ;;
    *)             echo other ;;
  esac
}

# vcmp CURRENT FIXED : sets VC/VN/FIXV for tools with a single fixed version.
vcmp() {
  FIXV=$2
  if [ -z "$1" ]; then VC=unknown; VN=; return; fi
  if ver_ge "$1" "$2"; then VC=ok; else VC=behind; fi
  VN="fixed in $2"
}

fix_curl() {
  case $(where_from "$1") in
    brew) fix "brew update && brew upgrade curl ca-certificates" ;;
    *)
      if [ "$1" = /usr/bin/curl ] && [ "$(uname)" = Darwin ]; then
        fix "Apple's curl reads /etc/ssl/cert.pem and does not check revocation."
        fix "Apply the macOS bundle workaround (System trust store, below), or install Homebrew's curl"
        fix "and upgrade ca-certificates: brew install curl && brew upgrade ca-certificates"
      else
        fix "Update the OS ca-certificates package, or the CA bundle this curl uses (curl CA bundle >= 2026-10-20)."
      fi
      FIXSYS=1 ;;
  esac
}

fix_go() {
  [ "${2%%:*}" = trusted ] && { fix "This Go build trusts the compromised chain via the OS trust store: see System trust store below."; FIXSYS=1; }
  { [ "$VC" = behind ] || [ "$VC" = nofix ]; } || return 0
  case $(where_from "$1") in
    brew)   fix "Upgrade Go to $FIXV or later: brew upgrade go" ;;
    mise)   fix "Upgrade Go to $FIXV or later: mise use -g go@${FIXV%% *}" ;;
    asdf)   fix "Upgrade Go to $FIXV or later: asdf install golang ${FIXV%% *}" ;;
    golang) fix "Upgrade Go to $FIXV or later: download from https://go.dev/dl/ and replace /usr/local/go" ;;
    *)      fix "Upgrade Go to $FIXV or later (https://go.dev/dl/). Projects can also pin it with 'toolchain' in go.mod." ;;
  esac
}

fix_python() {
  local p=$1 cafile=$2 r1=$3 r2=$4 vc=$5 r3=$6
  if [ "${r1%%:*}" = trusted ]; then
    case $cafile in
      */etc/ca-certificates/*|*/etc/openssl*|*/Cellar/*)
        fix "Uses Homebrew's CA bundle: brew update && brew upgrade ca-certificates" ;;
      ""|None)
        fix "No default CA file is configured for this Python." ;;
      *)
        fix "Reads the OS CA bundle ($cafile): see System trust store below."; FIXSYS=1 ;;
    esac
  fi
  if [ "${r2%%:*}" = trusted ]; then
    fix "The certifi bundle trusts the compromised chain: python3 -m pip install --upgrade 'certifi>=2026.10.19'"
    fix "(use a virtualenv or pipx if the environment is externally managed)"
  fi
  if [ "${r3%%:*}" = trusted ]; then
    fix "pip itself accepts the compromised chain (it carries its own CA bundle): upgrade it to 26.2.2 or later."
    fix "(PIP_CERT=/path/to/patched-bundle.pem is a stop-gap.)"
  fi
  if [ "$vc" = behind ]; then
    fix "Upgrade pip and certifi: $p -m pip install --upgrade 'pip>=26.2.2' 'certifi>=2026.10.19'"
  fi
  if [ "$p" = /usr/bin/python3 ] && [ "$(uname)" = Darwin ]; then
    if [ "${r1%%:*}" = trusted ] || [ "${r3%%:*}" = trusted ] || [ "$vc" = behind ]; then
      fix "Apple's built-in pip: see Built-in pip (macOS) below."; FIXPIP=1
    fi
  fi
}

AWK_JAVA_ALIASES='/^Alias name:/{a=substr($0,13)} /^Owner:/ && /CN=(AAA Certificate Services|emSign ECC Root CA - G3)/{print a}'

# java_cacerts JAVA_HOME : path of the JDK's default trust store, if present.
java_cacerts() {
  if [ -f "$1/lib/security/cacerts" ]; then echo "$1/lib/security/cacerts"
  elif [ -f "$1/jre/lib/security/cacerts" ]; then echo "$1/jre/lib/security/cacerts"; fi
}

# java_affected_aliases KEYTOOL CACERTS : read-only; aliases whose subject is one of the two roots
# the advisory says to distrust. Matching on subject (not alias) because aliases differ by vendor.
java_affected_aliases() {
  "$1" -J-Duser.language=en -list -v -keystore "$2" -storepass changeit 2>/dev/null </dev/null | awk "$AWK_JAVA_ALIASES"
}

fix_java() {
  local h=$1 res=$2 how cac kt n
  how=$(where_from "$h")
  case $how in
    sdkman) fix "sdk list java   # pick a build at or above $FIXV, then:"
            fix "sdk install java <identifier> && sdk default java <identifier>"
            fix "sdk uninstall java $(basename "$h")   # once nothing depends on it" ;;
    brew)   fix "brew update && brew upgrade openjdk   # or: brew upgrade --cask temurin" ;;
    *)
      case $h in
        /Library/Java/*|*/Library/Java/*) fix "Install the vendor's latest update for this line ($FIXV or later) and remove the old JDK." ;;
        /usr/lib/jvm/*|/usr/java/*)       fix "Upgrade the distro's JDK/JRE package (apt/dnf/zypper) to $FIXV or later." ;;
        *)                                fix "Install $FIXV or later from your JDK vendor and point JAVA_HOME at it." ;;
      esac ;;
  esac
  fix "Java uses its own cacerts/distrust list, so OS-level workarounds do not help; update the JDK."
  cac=$(java_cacerts "$h")
  kt=$h/bin/keytool
  if [ -n "$cac" ] && [ -x "$kt" ]; then
    n=$(java_affected_aliases "$kt" "$cac" | grep -c .)
    if [ "$n" -gt 0 ]; then
      fix "Stop-gap if no fixed build is available yet (this JDK's cacerts holds $n of the roots to distrust;"
      fix "the script has not tested that removing them stops the probe connecting):"
      fix "  R=\"$cac\"      # prefix commands with sudo if you cannot write to it"
      fix "  cp -p \"\$R\" \"\$R.pre-emudhra\""
      fix "  \"$kt\" -J-Duser.language=en -list -v -keystore \"\$R\" -storepass changeit | awk '$AWK_JAVA_ALIASES' |"
      fix "    while IFS= read -r a; do \"$kt\" -delete -alias \"\$a\" -keystore \"\$R\" -storepass changeit; done"
      fix "  Side effects: Java will reject sites chained to those roots (some Sectigo-issued certificates), and a"
      fix "  JDK upgrade restores them. Undo with: cp -p \"\$R.pre-emudhra\" \"\$R\""
    elif [ "${res%%:*}" = trusted ]; then
      fix "The default cacerts has none of the roots to distrust (or its password is not 'changeit'); check for a"
      fix "custom truststore: -Djavax.net.ssl.trustStore, JAVA_TOOL_OPTIONS or JDK_JAVA_OPTIONS."
    fi
  fi
}

# --------------------------------------------------------------- more probes

cat > "$TMP/node_probe.js" <<'EOF'
const https = require('https');
const urls = process.argv.slice(2);
let i = 0;
function next() {
  if (i >= urls.length) return;
  const u = urls[i++];
  const req = https.get(u, { timeout: 10000 }, function (res) {
    res.resume();
    console.log('ok', u);
    next();
  });
  req.on('timeout', function () { req.destroy(new Error('timeout')); });
  req.on('error', function (e) {
    const c = String(e.code || '');
    const cert = /CERT|UNABLE_TO_VERIFY|UNABLE_TO_GET_ISSUER|SELF_SIGNED|DEPTH_ZERO/.test(c);
    console.error('    error: ' + e.message);
    console.log(cert ? 'certerr' : 'err', u);
    next();
  });
}
next();
EOF

cat > "$TMP/deno_probe.js" <<'EOF'
for (const u of Deno.args) {
  try {
    const r = await fetch(u);
    await r.body?.cancel();
    console.log("ok", u);
  } catch (e) {
    const m = String(e);
    console.error("    error: " + m);
    console.log(/certificate|UnknownIssuer|Revoked|invalid peer/i.test(m) ? "certerr" : "err", u);
  }
}
EOF

cat > "$TMP/bun_probe.js" <<'EOF'
const urls = process.argv.slice(2);
for (const u of urls) {
  try {
    const r = await fetch(u);
    await r.arrayBuffer();
    console.log("ok", u);
  } catch (e) {
    const m = String(e) + " " + (e && e.code ? e.code : "");
    console.error("    error: " + m);
    console.log(/CERT|certificate|UNABLE_TO|SELF_SIGNED/i.test(m) ? "certerr" : "err", u);
  }
}
EOF

# runtime_probe BIN ARGS... : run a probe command against control + test hosts.
runtime_probe() {
  if [ "$NO_NETWORK" -eq 1 ]; then PROBE_RES="skipped:--no-network"; return; fi
  local out
  log_cmd "$* <urls>"
  out=$("$@" $CONTROL_URL $BAD_URLS 2>"$TMP/err" </dev/null)
  show_err
  PROBE_RES=$(printf '%s\n' "$out" | judge)
}

# probe_cafile FILE : test a PEM bundle using whichever Python the audit found.
probe_cafile() {
  if [ "$NO_NETWORK" -eq 1 ]; then echo "skipped:--no-network"; return; fi
  if [ -z "$PYBIN" ]; then echo "skipped:no Python available to test this bundle - version check only"; return; fi
  local out
  log_cmd "$PYBIN -I <tmp>/py_probe.py cafile $1 <urls>"
  out=$("$PYBIN" -I "$TMP/py_probe.py" cafile "$1" $CONTROL_URL $BAD_URLS 2>"$TMP/err" </dev/null)
  show_err
  printf '%s\n' "$out" | judge
}

# ------------------------------------------------------------------- Node.js

check_node_version() {
  local v=${1#v} major
  FIXV=
  major=${v%%.*}
  case $major in
    22) FIXV=22.23.4 ;;
    24) FIXV=24.22.1 ;;
    26) FIXV=26.12.1 ;;
    "") VC=unknown; VN=; return ;;
    *)
      if [ "$major" -gt 26 ]; then VC=ok; VN="newer than the fixed lines"
      else VC=nofix; VN="fixes only published for 22.23.4, 24.22.1, 26.12.1"; FIXV="22.23.4, 24.22.1 or 26.12.1"; fi
      return ;;
  esac
  vcmp "$v" "$FIXV"
}

node_candidates() {
  local d
  command -v node 2>/dev/null
  for d in "$HOME"/.nvm/versions/node/*/bin/node "$HOME"/.volta/tools/image/node/*/bin/node \
           "$HOME"/.local/share/fnm/node-versions/*/installation/bin/node \
           "$HOME"/Library/Application\ Support/fnm/node-versions/*/installation/bin/node \
           "$HOME"/.asdf/installs/nodejs/*/bin/node "$HOME"/.local/share/mise/installs/node/*/bin/node \
           /opt/homebrew/opt/node*/bin/node /usr/local/opt/node*/bin/node /usr/local/bin/node /usr/bin/node; do
    [ -x "$d" ] && echo "$d"
  done
}

fix_node() {
  local n=$1 how
  how=$(where_from "$n")
  case $how in
    nvm)   fix "nvm install $FIXV && nvm alias default $FIXV   # then: nvm uninstall $(basename "$(dirname "$(dirname "$n")")")" ;;
    volta) fix "volta install node@$FIXV" ;;
    fnm)   fix "fnm install $FIXV && fnm default $FIXV" ;;
    mise)  fix "mise use -g node@$FIXV" ;;
    asdf)  fix "asdf install nodejs $FIXV && asdf global nodejs $FIXV" ;;
    brew)  fix "brew update && brew upgrade node" ;;
    *)     fix "Install Node.js $FIXV or later (https://nodejs.org/en/download or your package manager)." ;;
  esac
  fix "Node.js uses its own bundled CA list by default, so editing OS bundles does not normally change it"
  fix "(unless NODE_EXTRA_CA_CERTS or --use-system-ca is in play): upgrade the runtime."
  case ${NODE_SYSCA_RES%%:*} in
    rejected)
      fix "Stop-gap: run with --use-system-ca (or NODE_USE_SYSTEM_CA=1) so Node uses the OS trust store."
      fix "Tested here: with that flag Node rejects the chain, because this OS store already blocks it. That only"
      fix "holds while the OS store stays patched, so still upgrade the runtime." ;;
    trusted)
      fix "Tested here: --use-system-ca does not help; Node still accepts the chain with it (it may not apply the"
      fix "OS revocation block). Upgrading the runtime is the fix." ;;
    skipped)
      fix "This Node has no --use-system-ca, so upgrading is the only fix." ;;
  esac
  fix "(Fixed releases: 22.23.4, 24.22.1, 26.12.1.)"
}

audit_node() {
  section "Node.js"
  local found=0 n key v nres extra
  while IFS= read -r n; do
    [ -n "$n" ] && [ -x "$n" ] || continue
    key="node:$(resolve "$n")"
    first_time "$key" || continue
    found=1
    v=$("$n" --version 2>/dev/null </dev/null)
    check_node_version "$v"
    runtime_probe "$n" "$TMP/node_probe.js"
    nres=$PROBE_RES
    NODE_SYSCA_RES=
    if [ "${nres%%:*}" = trusted ]; then
      if "$n" --use-system-ca -e 0 >/dev/null 2>&1 </dev/null; then
        runtime_probe "$n" --use-system-ca "$TMP/node_probe.js"
        NODE_SYSCA_RES=$PROBE_RES
      else
        NODE_SYSCA_RES="skipped:no --use-system-ca"
      fi
    fi
    extra=$(env_notes NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA)
    [ -n "$NODE_SYSCA_RES" ] && extra="${extra:+$extra
}    detail:  with --use-system-ca: $(describe_probe "$NODE_SYSCA_RES")"
    if [ "${nres%%:*}" = trusted ] || [ "$VC" = behind ] || [ "$VC" = nofix ]; then fix_node "$n"; fi
    report "Node.js" "$n" "${v:-?}" "$VC" "$VN" "$nres" "$extra"
  done <<EOF
$(node_candidates | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && { echo "  not found"; echo; }
  return 0
}

# --------------------------------------------------------- Deno / Bun (probe)

audit_deno() {
  section "Deno"
  local d v found=0
  while IFS= read -r d; do
    [ -n "$d" ] && [ -x "$d" ] || continue
    first_time "deno:$(resolve "$d")" || continue
    found=1
    v=$("$d" --version 2>/dev/null </dev/null | awk 'NR==1{print $2}')
    vcmp "$v" 2.9.8
    runtime_probe "$d" run --no-prompt --allow-net "$TMP/deno_probe.js"
    { [ "${PROBE_RES%%:*}" = trusted ] || [ "$VC" = behind ]; } && fix "Upgrade Deno to 2.9.8 or later: deno upgrade   (or brew upgrade deno)"
    report "Deno" "$d" "${v:-?}" "$VC" "$VN" "$PROBE_RES"
  done <<EOF
$({ command -v deno 2>/dev/null; ls "$HOME"/.deno/bin/deno /opt/homebrew/bin/deno /usr/local/bin/deno 2>/dev/null; } | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && { echo "  not found"; echo; }
  return 0
}

audit_bun() {
  section "Bun"
  local b v found=0
  while IFS= read -r b; do
    [ -n "$b" ] && [ -x "$b" ] || continue
    first_time "bun:$(resolve "$b")" || continue
    found=1
    v=$("$b" --version 2>/dev/null </dev/null)
    runtime_probe "$b" run "$TMP/bun_probe.js"
    [ "${PROBE_RES%%:*}" = trusted ] && {
      fix "The page lists no fixed Bun release yet (pending). Watch https://emudhra.we-have-a-problem.com/"
      fix "and upgrade as soon as one ships: bun upgrade. Until then avoid Bun for sensitive outbound TLS."
    }
    report "Bun" "$b" "${v:-?}" na "no fixed release yet (listed as pending)" "$PROBE_RES"
  done <<EOF
$({ command -v bun 2>/dev/null; ls "$HOME"/.bun/bin/bun /opt/homebrew/bin/bun /usr/local/bin/bun 2>/dev/null; } | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && { echo "  not found"; echo; }
  return 0
}

# ------------------------------------------- version-only tools (rustup etc.)

# audit_simple LABEL BIN-NAME FIXED UPGRADE-COMMAND [EXTRA-CANDIDATE...]
audit_simple() {
  local label=$1 name=$2 fixed=$3 upg=$4 b v found=0 extra="$5"
  section "$label"
  while IFS= read -r b; do
    [ -n "$b" ] && [ -x "$b" ] || continue
    first_time "$name:$(resolve "$b")" || continue
    found=1
    v=$(version_of "$name" "$b")
    vcmp "$v" "$fixed"
    if [ "$VC" = behind ]; then
      fix "Upgrade $label to $fixed or later: $upg"
      [ "$name" = rustup ] && fix "Also check Rust projects: Cargo.lock should resolve rustls-webpki >= 0.103.16 and webpki-roots >= 1.0.10 (cargo update -p rustls-webpki -p webpki-roots)."
    fi
    report "$label" "$b" "${v:-?}" "$VC" "$VN" "skipped:no safe way to probe this tool's own TLS - version check only"
  done <<EOF
$({ command -v "$name" 2>/dev/null; for b in $extra; do [ -x "$b" ] && echo "$b"; done; } | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && { echo "  not found"; echo; }
  return 0
}

# version_of NAME BIN : print a bare dotted version for the tool.
version_of() {
  case $1 in
    mise)  "$2" --version 2>/dev/null </dev/null | awk 'NR==1{print $1}' ;;
    claude) "$2" --version 2>/dev/null </dev/null | awk 'NR==1{print $1}' ;;
    *)     "$2" --version 2>/dev/null </dev/null | awk 'NR==1{print $2}' ;;
  esac
}

# --------------------------------------------------- Homebrew ca-certificates

audit_brew() {
  section "Homebrew ca-certificates"
  local b prefix link active norm bundle res
  b=$(command -v brew 2>/dev/null)
  if [ -z "$b" ]; then echo "  Homebrew not found"; echo; return 0; fi
  prefix=$(dirname "$(dirname "$(resolve "$b")")")
  BREW_PREFIX=$prefix
  link="$prefix/opt/ca-certificates"
  if [ ! -L "$link" ] && [ ! -d "$link" ]; then echo "  ca-certificates formula not installed"; echo; return 0; fi
  active=$(basename "$(readlink "$link" 2>/dev/null || echo "$link")")
  norm=$(printf '%s' "$active" | tr '_-' '..')
  vcmp "$norm" 2026.09.25.1
  VN="fixed in 2026-09-25_1"
  bundle="$prefix/etc/ca-certificates/cert.pem"
  if [ -f "$bundle" ]; then res=$(probe_cafile "$bundle"); else res="skipped:bundle $bundle not found"; fi
  if [ "${res%%:*}" = trusted ] || [ "$VC" = behind ]; then
    fix "brew update && brew upgrade ca-certificates"
    fix "(Homebrew's Python, curl, openssl and others read this bundle. Old versions linger in the Cellar;"
    fix " 'brew cleanup ca-certificates' removes them.)"
  fi
  report "Homebrew ca-certificates" "$link" "$active" "$VC" "$VN" "$res"
  return 0
}

# ------------------------------------------------------------ system CA bundles

audit_sysbundle() {
  section "System CA bundle files"
  local f key found=0 res brewb=
  [ -n "$BREW_PREFIX" ] && brewb=$(resolve "$BREW_PREFIX/etc/ca-certificates/cert.pem")
  for f in /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
           /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/ca-bundle.pem \
           /usr/local/share/certs/ca-root-nss.crt; do
    [ -f "$f" ] || continue
    key="bundle:$(resolve "$f")"
    [ -n "$brewb" ] && [ "$(resolve "$f")" = "$brewb" ] && continue
    first_time "$key" || continue
    found=1
    res=$(probe_cafile "$f")
    [ "${res%%:*}" = trusted ] && { fix "This bundle still contains the roots the compromised chain leads to: see System trust store below."; FIXSYS=1; }
    report "CA bundle" "$f" "file" na "no version; tested directly" "$res"
  done
  [ "$found" -eq 0 ] && { echo "  none found"; echo; }
  [ "$(uname)" = Darwin ] && echo "  Note: macOS's own trust store (Keychain) carries Apple's block since 19 Oct; tools that use it are protected."$'\n'
  return 0
}

# ---------------------------------------------------------------- OS packages

audit_ospkg() {
  section "OS CA packages"
  local id= vid= ver= fixed= mgr= vc=unknown vn= upg=
  if [ -r /etc/os-release ]; then
    id=$(. /etc/os-release; echo "$ID"); vid=$(. /etc/os-release; echo "$VERSION_ID")
  fi
  if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W ca-certificates >/dev/null 2>&1; then
    mgr=dpkg; ver=$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null)
    upg="sudo apt-get update && sudo apt-get install --only-upgrade ca-certificates"
    case $id in
      ubuntu) case $vid in 22.04|24.04|26.04|26.10) fixed="20260816ubuntu0.${vid}.1" ;; esac ;;
      debian) case $vid in 12) fixed="20250419~deb12u2" ;; 13) fixed="20250419+deb13u1" ;; *) fixed="20260816+nmu1" ;; esac ;;
    esac
    if [ -n "$fixed" ]; then
      if dpkg --compare-versions "$ver" ge "$fixed"; then vc=ok; else vc=behind; fi
      vn="fixed in $fixed"
    fi
  elif command -v apk >/dev/null 2>&1 && apk info -e ca-certificates >/dev/null 2>&1; then
    mgr=apk; ver=$(apk info -v ca-certificates 2>/dev/null | head -1 | sed 's/^ca-certificates-//')
    upg="apk update && apk upgrade ca-certificates"; fixed=20261020-r0; vn="fixed in $fixed"
    if [ "${ver%%-*}" -ge 20261020 ] 2>/dev/null; then vc=ok; else vc=behind; fi
  elif command -v pacman >/dev/null 2>&1 && pacman -Q ca-certificates-mozilla >/dev/null 2>&1; then
    mgr=pacman; ver=$(pacman -Q ca-certificates-mozilla 2>/dev/null | awk '{print $2}')
    upg="sudo pacman -Syu ca-certificates-mozilla"; fixed=3.131.1-1; vn="fixed in $fixed"
    if ver_ge "${ver%%-*}" 3.131.1; then vc=ok; else vc=behind; fi
  elif command -v rpm >/dev/null 2>&1 && rpm -q ca-certificates >/dev/null 2>&1; then
    mgr=rpm; ver=$(rpm -q --qf '%{VERSION}' ca-certificates 2>/dev/null)
    upg="sudo dnf upgrade ca-certificates"
    if [ "$id" = fedora ]; then
      fixed=2026.2.92_v9.0.319; vn="fixed in $fixed"
      if ver_ge "$ver" "$fixed"; then vc=ok; else vc=behind; fi
    else
      vn="the page lists no fixed package for this distribution"
    fi
  fi
  if [ -z "$mgr" ]; then
    echo "  no supported package manager / ca-certificates package found (not applicable here)"; echo
    return 0
  fi
  if [ "$vc" = behind ]; then
    fix "$upg"
    fix "If your distribution has not shipped the fix yet, use the workaround in System trust store (below)."
    FIXSYS=1
  fi
  report "ca-certificates ($mgr)" "$mgr" "${ver:-?}" "$vc" "$vn" "skipped:package check only; see the CA bundle results above"
  return 0
}

# --------------------------------------------------------------- Electron apps

check_electron_version() {
  local v=$1 major=${1%%.*}
  FIXV=
  case $major in
    42) FIXV=42.11.16 ;;
    43) FIXV=43.8.1 ;;
    44) FIXV=44.9.1 ;;
    "") VC=unknown; VN=; return ;;
    *)
      if [ "$major" -gt 44 ]; then VC=ok; VN="newer than the fixed lines"
      else VC=nofix; VN="fixes only published for 42.11.16, 43.8.1, 44.9.1"; FIXV="42.11.16, 43.8.1 or 44.9.1"; fi
      return ;;
  esac
  vcmp "$v" "$FIXV"
}

audit_electron() {
  section "Electron apps"
  if [ "$(uname)" != Darwin ]; then
    echo "  (macOS apps only for now - not checked on this platform)"; echo; return 0
  fi
  local f app v found=0
  for f in /Applications/*.app/Contents/Frameworks/"Electron Framework.framework"/Resources/Info.plist \
           "$HOME"/Applications/*.app/Contents/Frameworks/"Electron Framework.framework"/Resources/Info.plist; do
    [ -f "$f" ] || continue
    found=1
    app=${f%/Contents/Frameworks/*}
    v=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$f" 2>/dev/null)
    check_electron_version "$v"
    if [ "$VC" = behind ] || [ "$VC" = nofix ]; then
      fix "Update the app to a release built on Electron ${FIXV} (or newer) (check for an in-app update;"
      fix "if none exists yet, ask the vendor). You cannot patch the embedded runtime yourself."
    fi
    report "Electron app: $(basename "$app" .app)" "$app" "Electron ${v:-?}" "$VC" "$VN" "skipped:cannot probe an app's embedded runtime - version check only"
  done
  [ "$found" -eq 0 ] && { echo "  no Electron apps found"; echo; }
  return 0
}

# ------------------------------------------------------------------- git

# git_probe_all GIT : prints "<result> <url>" for the control and test hosts. git ls-remote
# against a non-repository: a TLS failure mentions the certificate; any HTTP-level answer
# ("not found", auth needed) means the handshake was accepted.
git_probe_all() {
  local u rc out
  export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=true
  cd "$TMP" || return
  for u in $CONTROL_URL $BAD_URLS; do
    run_to 25 "$1" -c http.lowSpeedLimit=1 -c http.lowSpeedTime=10 ls-remote "$u" \
      >/dev/null 2>"$TMP/gitout" </dev/null
    rc=$?
    if grep -qi 'certificate' "$TMP/gitout"; then out=certerr
    elif [ "$rc" -eq 0 ]; then out=ok
    elif grep -qi -E 'returned error|not found|not valid|is this a git repository|not a git repository|does not appear to be a git|authentication failed|could not read (username|password)' "$TMP/gitout"; then out=ok
    else out=err
    fi
    [ "$out" != ok ] && sed 's/^/    error: /' "$TMP/gitout" | head -3 >> "$TMP/err"
    echo "$out $u"
  done
}

fix_git() {
  [ "${2%%:*}" = trusted ] || return 0
  case $(where_from "$1") in
    brew) fix "brew update && brew upgrade git ca-certificates" ;;
    *)
      if [ "$1" = /usr/bin/git ] && [ "$(uname)" = Darwin ]; then
        fix "Apple's git reads /etc/ssl/cert.pem and does not check revocation: see System trust store below,"
        fix "or use Homebrew's git: brew install git && brew upgrade ca-certificates"
      else
        fix "git uses the OS/curl CA bundle (http.sslCAInfo or GIT_SSL_CAINFO if set): update ca-certificates,"
        fix "or see System trust store below."
      fi
      FIXSYS=1 ;;
  esac
}

audit_git() {
  section "git"
  local found=0 g v res out cfg extra
  while IFS= read -r g; do
    [ -n "$g" ] && [ -x "$g" ] || continue
    # macOS /usr/bin/git is a stub that prompts to install the Command Line Tools.
    if [ "$g" = /usr/bin/git ] && [ "$(uname)" = Darwin ] && ! xcode-select -p >/dev/null 2>&1; then continue; fi
    first_time "git:$(resolve "$g")" || continue
    found=1
    v=$("$g" --version 2>/dev/null </dev/null | awk '{print $3}')
    if [ "$NO_NETWORK" -eq 1 ]; then
      res="skipped:--no-network"
    else
      log_cmd "$g ls-remote <url>   (control + test hosts)"
      out=$(git_probe_all "$g")
      show_err
      res=$(printf '%s\n' "$out" | judge)
    fi
    extra=$(env_notes GIT_SSL_CAINFO GIT_SSL_CAPATH SSL_CERT_FILE)
    cfg=$(cd "$TMP" && "$g" config --get http.sslCAInfo 2>/dev/null </dev/null)
    [ -n "$cfg" ] && extra="${extra:+$extra
}    note:    http.sslCAInfo=$cfg"
    cfg=$(cd "$TMP" && "$g" config --get http.sslVerify 2>/dev/null </dev/null)
    [ "$cfg" = false ] && extra="${extra:+$extra
}    note:    http.sslVerify=false - git skips certificate checks"
    fix_git "$g" "$res"
    report "git" "$g" "${v:-?}" na "no fixed git version; depends on the CA bundle in use" "$res" "$extra"
  done <<EOF
$({ command -v git 2>/dev/null; ls /opt/homebrew/bin/git /usr/local/bin/git /usr/bin/git 2>/dev/null; } | awk '!s[$0]++')
EOF
  [ "$found" -eq 0 ] && { echo "  not found"; echo; }
  return 0
}

# --------------------------------------------------------- guidance (printing)

print_sys_guidance() {
  local id= like= all
  if [ -r /etc/os-release ]; then
    id=$(. /etc/os-release; echo "$ID"); like=$(. /etc/os-release; echo "$ID_LIKE")
  fi
  all="$id $like $(uname -s)"
  echo "  System trust store (for tools that read the OS CA bundle)"
  echo "    Preferred: install your OS vendor's fixed CA package/update. If none is available yet, the page's"
  echo "    workaround distrusts the two roots the compromised intermediates chain to ('AAA Certificate"
  echo "    Services' by Comodo, and 'emSign ECC Root CA - G3'). That can break legitimate sites which chain"
  echo "    to those roots, so keep the backup, test, and re-run this audit afterwards."
  echo
  case $all in
    *Darwin*)
      cat <<'EOF'
    macOS - /etc/ssl/cert.pem (read by the built-in curl, git, python3, perl, ruby, openssl):
      sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.bak &&
      sudo awk '/^(###|===) /{skip=0}
        /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
        !skip' /etc/ssl/cert.pem.bak | sudo tee /etc/ssl/cert.pem > /dev/null
      (An OS update may replace this file. Others report that macOS updates do not refresh it, so re-run
       the audit after updating rather than assuming either way.)
EOF
      ;;
    *alpine*)
      cat <<'EOF'
    Alpine:
      apk add ca-certificates &&
      sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' /etc/ca-certificates.conf && update-ca-certificates
EOF
      ;;
    *debian*|*ubuntu*|*devuan*)
      cat <<'EOF'
    Debian / Ubuntu (run as root):
      sed -i \
        -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
        -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \
        /etc/ca-certificates.conf && update-ca-certificates
EOF
      ;;
    *fedora*|*rhel*|*centos*|*rocky*|*almalinux*|*amzn*)
      cat <<'EOF'
    Fedora / RHEL / CentOS / Rocky / Alma / Amazon Linux 2023 (run as root):
      d=/etc/pki/ca-trust/source/blocklist; [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist
      trust extract --overwrite --format=pem-bundle \
        --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \
        $d/Comodo_AAA_Services_root.pem &&
      trust extract --overwrite --format=pem-bundle \
        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
        $d/emSign_ECC_Root_CA_-_G3.pem &&
      update-ca-trust
EOF
      ;;
    *suse*|*sles*)
      cat <<'EOF'
    openSUSE / SLES (run as root):
      d=/etc/pki/trust/blocklist; [ -d $d ] || d=/etc/pki/trust/blacklist
      trust extract --format=pem-bundle \
        --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \
        $d/Comodo_AAA_Services_root.pem &&
      trust extract --format=pem-bundle \
        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
        $d/emSign_ECC_Root_CA_-_G3.pem &&
      update-ca-certificates
EOF
      ;;
    *arch*)
      cat <<'EOF'
    Arch Linux (run as root):
      trust extract --format=pem-bundle \
        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
        /etc/ca-certificates/trust-source/blocklist/emSign_ECC_Root_CA_-_G3.pem &&
      update-ca-trust
EOF
      ;;
    *nixos*)
      cat <<'EOF'
    NixOS (configuration.nix):
      security.pki.caCertificateBlacklist = [ "Comodo AAA Services root" "emSign ECC Root CA - G3" ];
EOF
      ;;
    *FreeBSD*)
      cat <<'EOF'
    FreeBSD 14+ (run as root):
      cp /etc/ssl/certs/14bc7599.0 /usr/share/certs/untrusted/14bc7599.pem
      cp /etc/ssl/certs/ee64a828.0 /usr/share/certs/untrusted/ee64a828.pem
      certctl rehash
EOF
      ;;
    *NetBSD*)
      cat <<'EOF'
    NetBSD 10+ (run as root):
      certctl untrust /usr/share/certs/mozilla/all/emSign_ECC_Root_CA_-_G3.pem &&
      certctl untrust /usr/share/certs/mozilla/all/Comodo_AAA_Services_root.pem
EOF
      ;;
    *MINGW*|*MSYS*|*CYGWIN*)
      echo "    Windows: use Block-EmudhraCompromisedCA.ps1 from the page (elevated PowerShell)."
      echo "    The page does not recommend this for enterprise-managed devices."
      ;;
    *)
      echo "    No recipe for this platform here - see https://emudhra.we-have-a-problem.com/ ."
      ;;
  esac
  echo
}

print_pip_guidance() {
  echo "  Built-in pip (macOS)"
  echo "    Apple's pip does its own certificate handling; the page's fix points it at the system bundle."
  echo "    Do this after the System trust store workaround above:"
  cat <<'EOF'
      F="$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')/sitecustomize.py" &&
      echo 'import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")' | sudo tee -a "$F" > /dev/null &&
      sudo chmod 644 "$F"
EOF
  echo
  echo "    Alternatively avoid Apple's python3/pip: use Homebrew Python or a virtualenv with pip >= 26.2.2."
  echo
}

print_guidance() {
  [ "$NO_GUIDE" -eq 1 ] && return 0
  [ -z "$GUIDE" ] && [ -z "$ADVISE" ] && return 0
  section "Remediation guidance"
  echo "  This script only prints guidance; nothing below has been run. Commands that edit system trust"
  echo "  files need sudo - read them first. Upgrading is better than distrusting roots where it is possible."
  echo
  if [ -n "$GUIDE" ]; then
    printf '%s%sAffected - fix these first%s\n' "$C_BLD" "$C_RED" "$C_OFF"
    printf '%s' "$GUIDE"
    [ "$NEED_SYS" = 1 ] && print_sys_guidance
    [ "$NEED_PIPMAC" = 1 ] && print_pip_guidance
  fi
  if [ -n "$ADVISE" ]; then
    printf '%s%sProtected today, but older than the fixed release - upgrade when convenient%s\n' "$C_BLD" "$C_YEL" "$C_OFF"
    printf '%s' "$ADVISE"
  fi
  echo "  After changing anything, re-run this script to confirm."
  echo
}

# ------------------------------------------------------------------- main

printf '%seMudhra intermediate CA compromise - developer tool audit%s (v%s, read-only)\n' "$C_BLD" "$C_OFF" "$VERSION_OF_SCRIPT"
printf 'Host: %s   Date: %s\n' "$(uname -srm)" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
printf 'Reference: https://emudhra.we-have-a-problem.com/\n'
if [ "$NO_NETWORK" -eq 1 ]; then
  echo "Mode: version checks only (--no-network)"
else
  echo "Probe hosts: $BAD_URLS (control: $CONTROL_URL)"
fi
echo

audit_env
audit_curl
audit_git
audit_go
audit_python
audit_java
audit_node
audit_deno
audit_bun
audit_simple "rustup" rustup 1.29.2 "rustup self update   (or: brew upgrade rustup)" "$HOME/.cargo/bin/rustup"
audit_simple "uv" uv 0.13.4 "uv self update   (or: brew upgrade uv / pipx upgrade uv)" "$HOME/.local/bin/uv $HOME/.cargo/bin/uv"
audit_simple "pixi" pixi 0.82.1 "pixi self-update   (or: brew upgrade pixi)" "$HOME/.pixi/bin/pixi"
audit_simple "mise" mise 2026.10.17 "mise self-update   (or: brew upgrade mise)" "$HOME/.local/bin/mise"
audit_simple "Claude Code" claude 2.1.303 "claude update" "$HOME/.local/bin/claude $HOME/.claude/local/claude"
audit_brew
audit_sysbundle
audit_ospkg
audit_electron

section "Summary"
printf '  affected / likely affected: %s\n  ok / likely ok:             %s\n  unknown:                    %s\n' "$N_BAD" "$N_OK" "$N_UNK"
echo
echo "Notes: 'AFFECTED'/'OK' come from a live probe. 'LIKELY-*' are version-only."
echo "Not covered yet: Rust crates in your projects (rustls-webpki, webpki-roots), Perl Mozilla::CA, Composer,"
echo "Elixir/Erlang, containers and per-project virtualenvs/node_modules."
echo

print_guidance

[ "$N_BAD" -gt 0 ] && exit 1
exit 0
