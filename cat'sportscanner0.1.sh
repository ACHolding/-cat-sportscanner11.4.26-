#!/usr/bin/env bash
# cat's port scanner 0.1.2 — repaired Bash edition
# (c) Kondo Solutions 1999–2026
#
# TCP connect scanning using Bash /dev/tcp. Scan systems you own or are authorized to test.
# Requires: bash >= 4.3, GNU coreutils (timeout, or gtimeout on macOS), sort, tr, head, mktemp.
set -uo pipefail

VERSION=0.1.2
HOST_SPEC='' PORT_SPEC='' TIMEOUT=2 MAXJOBS=64
GRAB_BANNER=0 OUTFILE='' PROBE='' SHOW_CLOSED=0 VERBOSE=0
PORT_GIVEN=0
BANNER_MAX=200
DEFAULT_PORTS='21,22,23,25,53,80,110,111,135,139,143,443,445,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443'

usage() { cat <<HELP
 /\_/\\  cat's port scanner $VERSION
( o.o ) (c) Kondo Solutions 1999–2026
 > ^ <
Usage: $(basename -- "$0") -h HOST [-p PORTS] [options]

  -h HOST     hostname, IPv4, IPv4 last-octet range, or IPv4 CIDR /24–/32
  -p PORTS    comma-separated ports and ranges (default: common ports)
  -t SEC      connect/banner timeout, positive integer (default: 2)
  -c N        maximum parallel connections, 1–512 (default: 64)
  -b          attempt to read banners
  -P STR      send probe before reading banner (implies -b)
  -o FILE     save plain-text results
  -a          show closed/filtered ports
  -v          verbose progress
  --version   show version
  --help      show this help
  --          end of options; the next argument is the host

Example: $(basename -- "$0") -h 127.0.0.1 -p 22,80,8000-8010 -b
HELP
}

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

# mapfile, wait -n and ${var//pat/} all need bash 4.3+. /bin/bash on macOS is 3.2.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
  die "bash 4.3 or newer required (found $BASH_VERSION; on macOS: brew install bash)"
fi

valid_ipv4() {
  local ip=$1 x; local -a oct
  [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a oct <<< "$ip"
  for x in "${oct[@]}"; do (( 10#$x <= 255 )) || return 1; done
}

expand_hosts() {
  local spec=$1 prefix lo hi i ip mask block start last
  if [[ $spec =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})-([0-9]{1,3})$ ]]; then
    prefix=${BASH_REMATCH[1]}
    lo=$((10#${BASH_REMATCH[2]})); hi=$((10#${BASH_REMATCH[3]}))
    valid_ipv4 "$prefix.0" || die "invalid IPv4 prefix: $prefix"
    (( lo <= hi && hi <= 255 )) || die "invalid host range: $spec"
    for ((i=lo;i<=hi;i++)); do printf '%s.%d\n' "$prefix" "$i"; done
  elif [[ $spec == */* ]]; then
    ip=${spec%/*}; mask=${spec#*/}
    valid_ipv4 "$ip" || die "invalid IPv4 CIDR address: $ip"
    [[ $mask =~ ^(2[4-9]|3[0-2])$ ]] || die 'CIDR mask must be /24 through /32'
    prefix=${ip%.*}; last=$((10#${ip##*.}))
    block=$((1 << (32-mask))); start=$((last / block * block))
    for ((i=start;i<start+block;i++)); do printf '%s.%d\n' "$prefix" "$i"; done
  elif [[ $spec =~ ^[0-9.]+$ ]]; then
    valid_ipv4 "$spec" || die "invalid IPv4 address: $spec"
    printf '%s\n' "$spec"
  elif [[ $spec =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]]; then
    (( ${#spec} <= 253 )) || die "hostname too long: $spec"
    printf '%s\n' "$spec"
  else
    die "invalid host: $spec"
  fi
}

expand_ports() {
  local spec=$1 part lo hi p; local -a parts
  [[ -n $spec ]] || die 'empty port specification'
  IFS=, read -r -a parts <<< "$spec"
  for part in "${parts[@]}"; do
    part=${part//[[:space:]]/}
    [[ -n $part ]] || die 'empty entry in port list'
    if [[ $part =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
      lo=$((10#${BASH_REMATCH[1]})); hi=$((10#${BASH_REMATCH[2]}))
      (( lo >= 1 && hi <= 65535 && lo <= hi )) || die "invalid port range: $part"
      for ((p=lo;p<=hi;p++)); do printf '%d\n' "$p"; done
    elif [[ $part =~ ^[0-9]{1,5}$ ]]; then
      p=$((10#$part)); (( p >= 1 && p <= 65535 )) || die "invalid port: $part"
      printf '%d\n' "$p"
    else
      die "invalid port specification: $part"
    fi
  done | sort -nu
}

service_of() {
  case $1 in
    21) printf '%s\n' ftp;; 22) printf '%s\n' ssh;; 23) printf '%s\n' telnet;;
    25) printf '%s\n' smtp;; 53) printf '%s\n' dns;; 80) printf '%s\n' http;;
    110) printf '%s\n' pop3;; 111) printf '%s\n' rpcbind;; 135) printf '%s\n' msrpc;;
    139) printf '%s\n' netbios;; 143) printf '%s\n' imap;; 389) printf '%s\n' ldap;;
    443) printf '%s\n' https;; 445) printf '%s\n' smb;; 587) printf '%s\n' submission;;
    993) printf '%s\n' imaps;; 995) printf '%s\n' pop3s;; 1433) printf '%s\n' mssql;;
    1521) printf '%s\n' oracle;; 2049) printf '%s\n' nfs;; 3306) printf '%s\n' mysql;;
    3389) printf '%s\n' rdp;; 5432) printf '%s\n' postgres;; 5900) printf '%s\n' vnc;;
    6379) printf '%s\n' redis;; 8080) printf '%s\n' http-alt;; 8443) printf '%s\n' https-alt;;
    9200) printf '%s\n' elasticsearch;; 27017) printf '%s\n' mongodb;;
    *) printf '%s\n' unknown;;
  esac
}

while (($#)); do
  case $1 in
    -h|-p|-t|-c|-P|-o)
      (($# >= 2)) || die "missing value for $1"
      case $1 in
        -h) HOST_SPEC=$2 ;;
        -p) PORT_SPEC=$2; PORT_GIVEN=1 ;;
        -t) TIMEOUT=$2 ;;
        -c) MAXJOBS=$2 ;;
        -P) PROBE=$2; GRAB_BANNER=1 ;;
        -o) OUTFILE=$2 ;;
      esac
      shift 2 ;;
    -b) GRAB_BANNER=1; shift ;;
    -a) SHOW_CLOSED=1; shift ;;
    -v) VERBOSE=1; shift ;;
    --version) printf "cat's port scanner %s\n" "$VERSION"; exit 0 ;;
    --help) usage; exit 0 ;;
    --)
      shift
      (($#)) || die 'no host given after --'
      [[ -z $HOST_SPEC ]] || die 'host specified twice'
      HOST_SPEC=$1; shift
      (($#)) && die "unexpected argument: $1" ;;
    -?*) die "unknown argument: $1" ;;
    *)
      [[ -z $HOST_SPEC ]] || die "unexpected argument: $1"
      HOST_SPEC=$1; shift ;;
  esac
done

[[ -n $HOST_SPEC ]] || { usage >&2; die 'target required (-h)'; }
[[ $TIMEOUT =~ ^[0-9]{1,5}$ ]] || die 'timeout must be a positive integer'
[[ $MAXJOBS =~ ^[0-9]{1,5}$ ]] || die 'concurrency must be a positive integer'
TIMEOUT=$((10#$TIMEOUT)); MAXJOBS=$((10#$MAXJOBS))
(( TIMEOUT >= 1 )) || die 'timeout must be >= 1'
(( MAXJOBS >= 1 && MAXJOBS <= 512 )) || die 'concurrency must be 1-512'

# GNU timeout, or gtimeout on macOS / Homebrew coreutils.
TIMEOUT_BIN=''
for c in timeout gtimeout; do
  if command -v "$c" >/dev/null 2>&1; then TIMEOUT_BIN=$c; break; fi
done
[[ -n $TIMEOUT_BIN ]] || die 'GNU timeout required (on macOS: brew install coreutils)'

(( PORT_GIVEN )) || PORT_SPEC=$DEFAULT_PORTS

# Process substitution hides function failures, so expand to files and check errors explicitly.
TMP_SCAN=$(mktemp -d) || die 'cannot create temporary directory'

cleanup() {
  trap - EXIT INT TERM
  local p
  for p in $(jobs -pr); do kill "$p" 2>/dev/null; done
  [[ -n ${TMP_SCAN:-} ]] && rm -rf -- "$TMP_SCAN"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

expand_hosts "$HOST_SPEC" > "$TMP_SCAN/hosts" || exit 2
expand_ports "$PORT_SPEC" > "$TMP_SCAN/ports" || exit 2
mapfile -t HOSTS < "$TMP_SCAN/hosts"
mapfile -t PORTS < "$TMP_SCAN/ports"
(( ${#HOSTS[@]} > 0 && ${#PORTS[@]} > 0 )) || die 'empty host or port list'

if [[ -n $OUTFILE ]]; then
  [[ $OUTFILE != */* || -d ${OUTFILE%/*} ]] || die "no such directory: ${OUTFILE%/*}"
  : > "$OUTFILE" || die "cannot write output: $OUTFILE"
fi

TOTAL=$(( ${#HOSTS[@]} * ${#PORTS[@]} ))
printf "cat's port scanner %s - %d hosts x %d ports; timeout %ss; jobs %d\n" \
  "$VERSION" "${#HOSTS[@]}" "${#PORTS[@]}" "$TIMEOUT" "$MAXJOBS"
(( TOTAL <= 100000 )) || printf 'note: %d probes queued, this will take a while\n' "$TOTAL" >&2

START=$SECONDS

scan_port() {
  local host=$1 port=$2 idx=$3 banner='' svc f
  f=$TMP_SCAN/result.$idx
  # Positional arguments prevent shell injection from hostnames.
  if "$TIMEOUT_BIN" "$TIMEOUT" bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$host" "$port" 2>/dev/null; then
    svc=$(service_of "$port")
    printf '[OPEN] %s:%s %s\n' "$host" "$port" "$svc" > "$f"
    if (( GRAB_BANNER )); then
      banner=$("$TIMEOUT_BIN" "$TIMEOUT" bash -c '
        exec 3<>/dev/tcp/"$1"/"$2" || exit 1
        if [[ -n $3 ]]; then printf "%b\r\n" "$3" >&3; fi
        IFS= read -r -t "$4" line <&3 || :
        printf "%s" "$line"
      ' _ "$host" "$port" "$PROBE" "$TIMEOUT" 2>/dev/null \
        | tr -cd '\11\12\40-\176' | head -c "$BANNER_MAX" | tr '\11\12' '  ')
      if [[ $banner == *[![:space:]]* ]]; then
        printf '       %s\n' "${banner%"${banner##*[![:space:]]}"}" >> "$f"
      fi
    fi
  elif (( SHOW_CLOSED )); then
    printf '[----] %s:%s\n' "$host" "$port" > "$f"
  fi
}

idx=0
running=0
for host in "${HOSTS[@]}"; do
  for port in "${PORTS[@]}"; do
    while (( running >= MAXJOBS )); do
      wait -n 2>/dev/null || :
      (( running > 0 )) && (( running -= 1 ))
    done
    scan_port "$host" "$port" "$idx" &
    (( running += 1 )); (( idx += 1 ))
    if (( VERBOSE && idx % 200 == 0 )); then printf 'queued %d scans\n' "$idx" >&2; fi
  done
done
wait

OPEN=0
for ((i=0;i<idx;i++)); do
  f=$TMP_SCAN/result.$i
  [[ -f $f ]] || continue
  [[ $(head -c 7 -- "$f") == '[OPEN] ' ]] && (( OPEN += 1 ))
  cat -- "$f"
  if [[ -n $OUTFILE ]]; then
    cat -- "$f" >> "$OUTFILE" || die "failed writing results to $OUTFILE"
  fi
done

printf '%d open of %d scanned in %ds\n' "$OPEN" "$idx" "$((SECONDS-START))"
[[ -z $OUTFILE ]] || printf 'results written to %s\n' "$OUTFILE"
exit 0