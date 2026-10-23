#!/usr/bin/env bash
#
# wp-php2shell-check.sh
#
# Read-only compromise check for WordPress sites on shared PHP hosting after PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619).
#
# Run this script ON the webspace, for example:
#   ssh user@host.example 'bash -s' < wp-php2shell-check.sh > report.md
#   ssh user@host.example 'bash -s -- --wp-cli --measure-php' < wp-php2shell-check.sh > report.md
#   (Add "-p PORT" if your host uses another SSH port.)
#
# The script writes a Markdown report to stdout and progress messages to stderr.
# It does not change application files. Two options write temporary files:
#   --measure-php  writes one random PHP file per web root and deletes it immediately.
#   --wp-cli       downloads wp-cli.phar to ~/data if it is missing and deletes it at the end.
#
# Copyright (c) 2026 Digital Heroes GmbH, Hamburg. MIT License.

set -o pipefail
export LC_ALL=C

VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

SINCE="2026-10-20"
BASELINE_DAYS=6
HTML_DIR=""   # empty: detect ~/html, ~/public_html, ~/httpdocs, ~/www or ~/htdocs
LOG_DIR=""    # empty: detect ~/logs, ~/log or ~/access-logs
DATA_DIR="$HOME/data"
MEASURE_PHP=0
USE_WPCLI=0
KEEP_WPCLI=0
PHP_BIN=""
TRUSTED_IPS=""
declare -A SITE_OVERRIDE=()

# Patched PHP versions per branch. Branches that are not in this list get no fix.
declare -A PHP_FIXED=( ["8.5"]="8.5.12" ["8.4"]="8.4.27" ["8.3"]="8.3.36" ["8.2"]="8.2.35" )


WPCLI_URL="https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
# Suspect code. PHP function names are not case-sensitive, so grep uses -i with this pattern.
SUSPECT_RE='eval[[:space:]]*\(|gzinflate|gzuncompress|str_rot13|shell_exec|passthru|proc_open|pcntl_exec|create_function|assert[[:space:]]*\(|base64_decode[[:space:]]*\(|\$_(GET|POST|REQUEST|COOKIE|SERVER)\[[^]]+\][[:space:]]*\('
# File extensions that PHP can execute.
PHPX_RE='\.(php[0-9]?|phtml|phar|inc)$'
STATIC_RE='\.(css|js|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|mp4|pdf)$'
ENTRY_RE='/(index|wp-login|wp-cron|xmlrpc|wp-comments-post|matomo|piwik|koko-analytics-collect)\.php$|^/wp-admin/'

usage() {
  cat <<'EOF'
Usage: wp-php2shell-check.sh [options]

Options:
  --since YYYY-MM-DD     Start of the time window (default: 2026-10-20)
  --html DIR             Directory with the web roots (default: detect ~/html, ~/public_html, ~/httpdocs, ~/www, ~/htdocs)
  --logs DIR             Directory with the access and error logs (default: detect ~/logs, ~/log, ~/access-logs)
  --site DOMAIN=PATH     Set the application root for a domain (repeat as necessary)
  --measure-php          Measure the PHP version over HTTP (writes and deletes a temp file)
  --wp-cli               Run WP-CLI checks (checksums, users, updates)
  --keep-wpcli           Do not delete wp-cli.phar at the end
  --php BIN              PHP binary for WP-CLI (default: newest php-8.x binary)
  --trusted-ip IP        IP that is known to the operator (repeat as necessary)
  -h, --help             Show this help
  -V, --version          Show the version
EOF
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE="$2"; shift 2 ;;
    --html) HTML_DIR="$2"; shift 2 ;;
    --logs) LOG_DIR="$2"; shift 2 ;;
    --site) SITE_OVERRIDE["${2%%=*}"]="${2#*=}"; shift 2 ;;
    --measure-php) MEASURE_PHP=1; shift ;;
    --wp-cli) USE_WPCLI=1; shift ;;
    --keep-wpcli) KEEP_WPCLI=1; shift ;;
    --php) PHP_BIN="$2"; shift 2 ;;
    --trusted-ip) TRUSTED_IPS="$TRUSTED_IPS $2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) echo "wp-php2shell-check $VERSION"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if ! date -d "$SINCE" +%s >/dev/null 2>&1; then
  echo "Error: --since must be a date in the format YYYY-MM-DD." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Temp files and cleanup
# ---------------------------------------------------------------------------

# Log extracts go to a private temp directory, not into shell variables (large logs).
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wp-php2shell-check.XXXXXX")" || {
  echo "Error: cannot create a temp directory." >&2; exit 2; }
TEMP_FILES=()
WPCLI_DOWNLOADED=0

# Remove all temp files, also when the operator stops the script with Ctrl+C.
cleanup() {
  local f
  for f in "${TEMP_FILES[@]}"; do
    case "$f" in */v[0-9a-f]*.php) rm -f -- "$f" ;; esac
  done
  if [ "$WPCLI_DOWNLOADED" = 1 ] && [ "$KEEP_WPCLI" = 0 ]; then
    rm -f -- "$DATA_DIR/wp-cli.phar" "$DATA_DIR/wp-cli.phar.part"
    printf '[wp-php2shell-check] %s\n' "Removed $DATA_DIR/wp-cli.phar" >&2
  fi
  case "$WORK_DIR" in */wp-php2shell-check.*) rm -rf -- "$WORK_DIR" ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[wp-php2shell-check] %s\n' "$*" >&2; }

# Make a regex that matches all log dates from FIRST to LAST (format 21/Oct/2026).
day_regex() {
  local first="$1" last="$2" day out=""
  day="$first"
  while [ "$(date -d "$day" +%s)" -le "$(date -d "$last" +%s)" ]; do
    out="${out:+$out|}$(date -d "$day" +%d/%b/%Y)"
    day="$(date -d "$day + 1 day" +%F)"
  done
  printf '(%s)' "${out//\//\\/}"
}

TODAY="$(date -u +%F)"
if [ "$(date -d "$SINCE" +%s)" -gt "$(date -d "$TODAY" +%s)" ]; then
  echo "Error: --since must not be in the future." >&2
  exit 2
fi
WINDOW_RE="$(day_regex "$SINCE" "$TODAY")"
BASELINE_RE="$(day_regex "$(date -d "$SINCE - $BASELINE_DAYS days" +%F)" "$(date -d "$SINCE - 1 day" +%F)")"

# Print a version string as a number that sorts correctly (8.3.36 -> 8003036).
vnum() { awk -F. '{ printf "%d%03d%03d\n", $1, $2, $3 }' <<<"$1"; }

# Echo "ok" or "NOT OK" for a full PHP version.
php_verdict() {
  local full="$1" branch fixed
  branch="$(cut -d. -f1,2 <<<"$full")"
  fixed="${PHP_FIXED[$branch]:-}"
  if [ -z "$fixed" ]; then
    echo "NOT OK (no fix for branch $branch)"
  elif [ "$(vnum "$full")" -ge "$(vnum "$fixed")" ]; then
    echo "ok (fix: $fixed)"
  else
    echo "NOT OK (fix: $fixed)"
  fi
}

# Read log files (plain and gzip) in one stream.
read_logs() { [ $# -gt 0 ] && zcat -f -- "$@" 2>/dev/null; }

# Findings per site: SEVERITY|TEXT. SEVERITY is red, yellow or info.
declare -A FINDINGS=()
add_finding() { FINDINGS["$1"]+="$2|$3"$'\n'; }

site_status() {
  local f="${FINDINGS[$1]:-}"
  if grep -q '^red|' <<<"$f"; then echo "red"
  elif grep -q '^yellow|' <<<"$f"; then echo "yellow"
  else echo "green"; fi
}

md_code() { printf '```\n%s\n```\n' "$1"; }

# ---------------------------------------------------------------------------
# Site discovery
# ---------------------------------------------------------------------------

# Find the application root below a directory (max depth 3, follows symlinks).
find_app_root() {
  local base="$1" hit
  for marker in wp-config.php please console artisan; do
    hit="$(find -L "$base" -maxdepth 3 -name "$marker" -type f ! -path '*/vendor/*' ! -path '*/node_modules/*' \
           ! -path '*/releases/*' ! -path '*/bckp/*' ! -path '*/backup/*' 2>/dev/null | head -n1)"
    if [ -n "$hit" ]; then
      dirname "$(readlink -f "$hit")"
      return 0
    fi
  done
  readlink -f "$base"
}

detect_app() {
  local root="$1"
  if [ -f "$root/wp-config.php" ]; then
    echo "wordpress"
  elif [ -f "$root/please" ] && grep -q '"statamic/cms"' "$root/composer.json" 2>/dev/null; then
    echo "statamic"
  elif [ -f "$root/artisan" ]; then
    echo "laravel"
  elif [ -f "$root/console" ] && [ -f "$root/config/config.ini.php" ]; then
    echo "matomo"
  elif find "$root" -maxdepth 2 -name '*.php' -type f 2>/dev/null | grep -q .; then
    echo "php"
  else
    echo "static"
  fi
}

web_root_for() {
  case "$2" in
    statamic|laravel) echo "$1/public" ;;
    *) echo "$1" ;;
  esac
}

app_version() {
  local root="$1" app="$2" v=""
  case "$app" in
    wordpress) v="$(grep -oE "wp_version = '[^']+'" "$root/wp-includes/version.php" 2>/dev/null | cut -d"'" -f2)" ;;
    statamic) v="$(grep -A3 '"name": "statamic/cms"' "$root/composer.lock" 2>/dev/null | grep -oE '"version": "[^"]+"' | cut -d'"' -f4)" ;;
    matomo) v="$(grep -oE "VERSION = '[^']+'" "$root/core/Version.php" 2>/dev/null | cut -d"'" -f2)" ;;
  esac
  echo "${v:-?}"
}

declare -a DOMAINS=()
declare -A APP_ROOT=() APP=() WEB_ROOT=()

discover_sites() {
  local f d dir
  # Use rotated logs too, so that a domain without traffic today is not lost.
  while read -r d; do
    [ -n "$d" ] && [ "$d" != "complete" ] && DOMAINS+=("$d")
  done < <( { find "$LOG_DIR" -maxdepth 1 -name '*-access.log*' -printf '%f\n' 2>/dev/null \
               | sed -E 's/-access\.log.*$//'
             # Domains from --site are checked also when they have no access log.
             for d in "${!SITE_OVERRIDE[@]}"; do echo "$d"; done; } | sort -u)

  for d in "${DOMAINS[@]}"; do
    if [ -n "${SITE_OVERRIDE[$d]:-}" ]; then
      dir="${SITE_OVERRIDE[$d]}"
    elif [ -d "$HTML_DIR/$d" ]; then
      dir="$HTML_DIR/$d"
    elif [ -d "$HTML_DIR/${d//./_}" ]; then
      dir="$HTML_DIR/${d//./_}"
    elif [ "${#DOMAINS[@]}" -eq 1 ] && [ -f "$HTML_DIR/wp-config.php" ]; then
      # One site directly in the web root directory (common on cPanel and Plesk).
      dir="$HTML_DIR"
    else
      dir=""
    fi
    if [ -z "$dir" ]; then
      APP_ROOT[$d]=""
      APP[$d]="unknown"
      WEB_ROOT[$d]=""
      continue
    fi
    APP_ROOT[$d]="$(find_app_root "$dir")"
    APP[$d]="$(detect_app "${APP_ROOT[$d]}")"
    WEB_ROOT[$d]="$(web_root_for "${APP_ROOT[$d]}" "${APP[$d]}")"
  done
}

# ---------------------------------------------------------------------------
# Step 1: PHP versions
# ---------------------------------------------------------------------------

PHP_CLI_TABLE=""
PHP_CLI_OLD=""
PHP_WEB_TABLE=""

check_php_cli() {
  local bin full old=""
  for bin in $(compgen -c | grep -E '^php-?[0-9]+\.[0-9]+$' | sort -t. -k1,1V -k2,2n -u); do
    # Show only branches that get a fix. List the old binaries in one line.
    if [ -z "${PHP_FIXED[${bin#php-}]:-}" ]; then
      old="${old:+$old, }${bin#php-}"
      continue
    fi
    full="$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null)" || continue
    [ -n "$full" ] || continue
    PHP_CLI_TABLE+="| \`$bin\` | $full | $(php_verdict "$full") |"$'\n'
  done
  [ -n "$old" ] && PHP_CLI_OLD="Also installed (end of life, no fix; a risk only if a site uses them): $old"
}

check_php_web() {
  local d root name file out ver upl
  for d in "${DOMAINS[@]}"; do
    root="${WEB_ROOT[$d]}"
    [ -n "$root" ] && [ -d "$root" ] || continue
    case "${APP[$d]}" in static) continue ;; esac
    name="v$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n').php"
    file="$root/$name"
    # The temp file prints the PHP version and the session.upload_progress.enabled value.
    # Register it first, so that the trap removes it if the script stops during curl.
    TEMP_FILES+=("$file")
    printf '<?php echo PHP_VERSION, "|", (int) ini_get("session.upload_progress.enabled");' > "$file" || continue
    out="$(curl -s -m 20 "https://$d/$name" | head -c 40)"
    # Remove the temp file at once. The guard makes sure that the path is the temp file.
    case "$file" in */v[0-9a-f]*.php) rm -f -- "$file" ;; esac
    if [ -e "$file" ]; then
      add_finding "$d" red "Could not remove temp file \`$file\`. Remove it manually."
    fi
    if [[ "$out" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\|([01])$ ]]; then
      ver="${BASH_REMATCH[1]}"
      upl="off"; [ "${BASH_REMATCH[2]}" = 1 ] && upl="**on**"
      PHP_WEB_TABLE+="| $d | $ver | $(php_verdict "$ver") | $upl |"$'\n'
      case "$(php_verdict "$ver")" in
        NOT*) add_finding "$d" red "Web PHP $ver is not patched. Contact the hosting provider now." ;;
      esac
      [ "${BASH_REMATCH[2]}" = 1 ] && add_finding "$d" yellow \
        "\`session.upload_progress.enabled\` is on. PHP recommends 0 until the next release (CVE-2026-109619, CVE-2026-115560)."
    else
      PHP_WEB_TABLE+="| $d | no answer | check manually | ? |"$'\n'
    fi
  done
}

# ---------------------------------------------------------------------------
# Step 2a: file system
# ---------------------------------------------------------------------------

# True if the file is the Koko Analytics buffer (only "exit" plus data lines).
is_koko_buffer() {
  local f="$1"
  [ "$(basename "$f")" = "pageviews.php" ] || return 1
  [ "$(head -n1 "$f")" = "<?php exit; ?>" ] || return 1
  ! tail -n +2 "$f" | grep -qvE '^(p|e|r),[^<>]*$|^$'
}

check_filesystem() {
  local d="$1" root="${APP_ROOT[$1]}" web="${WEB_ROOT[$1]}" app="${APP[$1]}"
  local changed groups hits f dirs

  # Format: "YYYY-MM-DD HH:MM<TAB>path". The tab keeps paths with spaces intact.
  changed="$(find -L "$root" -type f -newerct "$SINCE" \
      ! -path '*/cache/*' ! -path '*/storage/framework/*' ! -path '*/tmp/*' ! -path '*/node_modules/*' \
      ! -path '*/releases/*' ! -path '*/.git/*' -printf '%CY-%Cm-%Cd %CH:%CM\t%p\n' 2>/dev/null | sort)"

  # Group changed files per component and minute. Updates show up as one big block.
  # The root prefix is removed with substr, not with a regex (paths can contain + or .).
  groups="$(awk -F'\t' -v r="$root/" 'NF >= 2 { p=$2; if (index(p, r) == 1) p = substr(p, length(r) + 1);
      n=split(p, a, "/");
      c = (a[1]=="wp-content" && (a[2]=="plugins" || a[2]=="themes") && n>3) ? a[1]"/"a[2]"/"a[3] : (a[1]=="wp-content" && n>2 ? a[1]"/"a[2] : (n>1 ? a[1] : "(root)"));
      print $1, c }' <<<"$changed" | sort | uniq -c | sort -k2,3)"
  CHANGED_COUNT[$d]="$(grep -c . <<<"$changed")"
  CHANGED_GROUPS[$d]="$groups"

  # New or changed files directly in the app root or in mu-plugins are a red criterion.
  while IFS=$'\t' read -r _ f; do
    [ -n "$f" ] || continue
    case "$f" in
      "$root"/*/*) case "$f" in "$root"/wp-content/mu-plugins/*) ;; *) continue ;; esac ;;
    esac
    case "$(basename "$f")" in
      error_log|*.log) add_finding "$d" info "Changed in app root: \`${f#"$root"/}\`" ;;
      *.php|*.phtml|*.phar|.htaccess|.user.ini)
        add_finding "$d" red "New or changed file in app root or mu-plugins: \`${f#"$root"/}\`" ;;
      *) add_finding "$d" yellow "New or changed file in app root: \`${f#"$root"/}\` (content update?)" ;;
    esac
  done <<<"$changed"

  # Suspect code (case-insensitive) in:
  #  - all changed files with a PHP-executable extension,
  #  - all PHP files in the app root and in mu-plugins, also if they are older than the window
  #    (a window that starts too late must not hide an old web shell).
  # Files of plugins that pass the checksum check are dropped later as noise.
  hits="$( { cut -f2- <<<"$changed"
             find "$root" -maxdepth 1 -type f 2>/dev/null
             find "$root/wp-content/mu-plugins" -type f 2>/dev/null; } \
           | grep -iE "$PHPX_RE" | sort -u | while IFS= read -r f; do
               [ -f "$f" ] && grep -liE "$SUSPECT_RE" -- "$f" 2>/dev/null; done)"
  SUSPECT_HITS[$d]="$hits"

  # .user.ini and .htaccess anywhere below the app root: auto_prepend_file and handlers that
  # make other file types executable run attacker code without a visible .php file.
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local rule
    rule="$(grep -iE 'auto_(prepend|append)_file|(AddType|AddHandler|SetHandler)[^#]*(php|phtml)' -- "$f" 2>/dev/null \
            | grep -vE '^[[:space:]]*#' | head -n 3)"
    [ -n "$rule" ] || continue
    if grep -qiE 'wordfence-waf\.php' <<<"$rule"; then
      add_finding "$d" info "Wordfence firewall loader in \`${f#"$root"/}\` (normal for Wordfence)."
    elif grep -qiE 'auto_(prepend|append)_file' <<<"$rule"; then
      add_finding "$d" red "\`auto_prepend_file\`/\`auto_append_file\` in \`${f#"$root"/}\`:"$'\n'"$rule"
    elif [[ "$f" == */uploads/* || "$f" == */assets/* ]]; then
      add_finding "$d" red "PHP handler in an upload folder: \`${f#"$root"/}\`:"$'\n'"$rule"
    else
      add_finding "$d" info "PHP handler rule in \`${f#"$root"/}\` (often set by the host or a cache plugin):"$'\n'"$rule"
    fi
  done < <(find -L "$root" \( -name .user.ini -o -name .htaccess -o -name php.ini \) -type f \
             ! -path '*/vendor/*' ! -path '*/node_modules/*' ! -path '*/releases/*' 2>/dev/null)

  # Hidden PHP files and PHP files with double extensions.
  while read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      *.php.cache|*/.php-cs-fixer*.php|*/.php_cs*) add_finding "$d" info "Tool file (normal): \`${f#"$root"/}\`" ;;
      *) add_finding "$d" yellow "Hidden or double-extension PHP file: \`${f#"$root"/}\`" ;;
    esac
  done < <(find -L "$root" -type f \( -name '.*.php' -o -iname '*.php.*' -o -iname '*.phtml' -o -iname '*.phar' \) \
             ! -path '*/vendor/*' ! -path '*/node_modules/*' ! -path '*/releases/*' 2>/dev/null)

  # PHP files in upload folders.
  local up=""
  case "$app" in
    wordpress) up="$root/wp-content/uploads" ;;
    statamic|laravel) up="$web" ;;
  esac
  if [ -n "$up" ] && [ -d "$up" ]; then
    while read -r f; do
      [ -n "$f" ] || continue
      [ "$f" = "$web/index.php" ] && continue
      if is_koko_buffer "$f"; then
        add_finding "$d" info "Koko Analytics buffer in uploads (normal): \`${f#"$root"/}\`"
      else
        add_finding "$d" red "PHP file in upload folder: \`${f#"$root"/}\` (sha256 $(sha256sum "$f" | cut -c1-16)...)"
      fi
    done < <(find -L "$up" -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' \) 2>/dev/null)
  fi

  # Directory changes without new files are often the WP-cron write test.
  dirs="$(find -L "$root" -maxdepth 3 -type d -newerct "$SINCE" ! -path '*/cache*' ! -path '*/updraft*' \
          ! -path '*/uploads*' ! -path '*/languages*' ! -path '*/upgrade*' ! -path '*/tmp*' \
          ! -path '*/storage*' -printf '%CY-%Cm-%Cd %CH:%CM:%CS  %p\n' 2>/dev/null | sort | sed "s#$root#.#")"
  DIR_CHANGES[$d]="$dirs"
}

# ---------------------------------------------------------------------------
# Step 2b: application checks
# ---------------------------------------------------------------------------

WPCLI=""

pick_php() {
  if [ -n "$PHP_BIN" ]; then echo "$PHP_BIN"; return; fi
  compgen -c | grep -E '^php-?8\.[0-9]+$' | sort -t. -k2,2n -u | tail -n1
}

prepare_wpcli() {
  [ "$USE_WPCLI" = 1 ] || return 1
  [ -n "$WPCLI" ] && return 0
  mkdir -p "$DATA_DIR"
  if [ ! -f "$DATA_DIR/wp-cli.phar" ]; then
    log "Downloading wp-cli.phar to $DATA_DIR"
    WPCLI_DOWNLOADED=1
    local want got
    # --fail: an HTTP error must not leave an HTML page as the phar.
    if ! curl -fsSL -o "$DATA_DIR/wp-cli.phar.part" "$WPCLI_URL"; then
      log "Download of wp-cli.phar failed. Skip WP-CLI."; return 1
    fi
    want="$(curl -fsSL "$WPCLI_URL.sha512" 2>/dev/null | grep -oE '^[0-9a-f]{128}')"
    got="$(sha512sum "$DATA_DIR/wp-cli.phar.part" | cut -d' ' -f1)"
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
      log "wp-cli.phar does not match the published SHA-512. Skip WP-CLI."
      rm -f -- "$DATA_DIR/wp-cli.phar.part"; return 1
    fi
    mv -- "$DATA_DIR/wp-cli.phar.part" "$DATA_DIR/wp-cli.phar"
  fi
  PHP_BIN="$(pick_php)"
  [ -n "$PHP_BIN" ] || { log "No versioned PHP binary found. Skip WP-CLI."; return 1; }
  # Send PHP notices to stderr, so that they do not mix with the WP-CLI output.
  WPCLI="$PHP_BIN -d display_errors=stderr -d error_reporting=E_ALL&~E_DEPRECATED $DATA_DIR/wp-cli.phar --skip-plugins --skip-themes"
}

check_wordpress() {
  local d="$1" root="${APP_ROOT[$1]}" out failed skipped admins newusers f slug perm
  perm="$(stat -c %a "$root/wp-config.php" 2>/dev/null)"
  case "$perm" in *[2367]) add_finding "$d" yellow "\`wp-config.php\` is world-writable (mode $perm). Use 640 or 600." ;; esac
  [ -d "$root/wp-content/plugins/wp-file-manager" ] && \
    add_finding "$d" yellow "Plugin \`wp-file-manager\` is installed. It has a long history of exploits."

  local mu
  mu="$(find "$root/wp-content/mu-plugins" -maxdepth 1 -mindepth 1 -printf '%f ' 2>/dev/null)"
  [ -n "$mu" ] && APP_NOTES[$d]+="mu-plugins (check that you know them): $mu"$'\n'

  prepare_wpcli || { APP_NOTES[$d]+="WP-CLI checks skipped (use --wp-cli)."$'\n'; return; }

  # shellcheck disable=SC2086
  out="$($WPCLI --path="$root" core verify-checksums 2>&1 | grep -v 'DS_Store')"
  local core_ok=0
  if grep -q '^Success' <<<"$out"; then
    core_ok=1
    APP_NOTES[$d]+="Core checksums: ok"$'\n'
  else
    add_finding "$d" red "Core checksums failed:"$'\n'"$(head -n 10 <<<"$out")"
  fi

  # shellcheck disable=SC2086
  out="$($WPCLI --path="$root" plugin verify-checksums --all 2>&1)"
  failed="$(awk -F'\t' 'NF>=3 && $1!="plugin_name" {print $1}' <<<"$out" | sort -u)"
  skipped="$(grep -oE 'of plugin [^ ,]+' <<<"$out" | awk '{print $3}' | sort -u)"
  APP_NOTES[$d]+="Plugin checksums: $(grep -E '^(Success|Error)' <<<"$out" | tail -n1)"$'\n'
  for slug in $failed; do
    if [ "$slug" = "hello" ]; then
      add_finding "$d" info "Plugin \`hello\` differs from wordpress.org. The core-bundled variant does this (normal if inactive)."
    else
      add_finding "$d" yellow "Plugin checksum mismatch: \`$slug\`"
    fi
  done
  PLUGINS_FAILED[$d]="$failed"
  PLUGINS_SKIPPED[$d]="$skipped"

  # shellcheck disable=SC2086
  admins="$($WPCLI --path="$root" user list --role=administrator --fields=ID,user_login,user_registered 2>&1)"
  APP_NOTES[$d]+="Administrators:"$'\n'"$admins"$'\n'
  # shellcheck disable=SC2086
  newusers="$($WPCLI --path="$root" user list --fields=ID,user_login,roles,user_registered 2>/dev/null \
              | awk -F'\t' -v s="$SINCE" '$1 ~ /^[0-9]+$/ && $4 >= s')"
  if [ -n "$newusers" ]; then
    add_finding "$d" red "Users registered since $SINCE:"$'\n'"$newusers"
  fi

  # shellcheck disable=SC2086
  out="$($WPCLI --path="$root" plugin list --update=available --fields=name,version,update_version 2>/dev/null)"
  [ "$(grep -c . <<<"$out")" -gt 1 ] && APP_NOTES[$d]+="Plugin updates available:"$'\n'"$out"$'\n'
  # shellcheck disable=SC2086
  out="$($WPCLI --path="$root" core check-update --fields=version,update_type 2>/dev/null)"
  grep -q 'Success' <<<"$out" || APP_NOTES[$d]+="Core updates available:"$'\n'"$out"$'\n'

  # Suspect-code hits inside plugins that pass the checksum check are noise.
  local keep=""
  while read -r f; do
    [ -n "$f" ] || continue
    slug="$(sed -nE 's#.*/wp-content/plugins/([^/]+)/.*#\1#p' <<<"$f")"
    if [ -n "$slug" ] && ! grep -qx "$slug" <<<"$failed"$'\n'"$skipped"; then continue; fi
    case "$f" in "$root"/wp-admin/*|"$root"/wp-includes/*) [ "$core_ok" = 1 ] && continue ;; esac
    # Core files in the root (index.php, wp-*.php, xmlrpc.php) are covered by the core checksums.
    # wp-config.php is not a core file and stays in the list.
    case "$f" in
      "$root"/wp-config.php) ;;
      "$root"/index.php|"$root"/xmlrpc.php|"$root"/wp-*.php) [ "$core_ok" = 1 ] && continue ;;
    esac
    keep+="$f"$'\n'
  done <<<"${SUSPECT_HITS[$d]}"
  SUSPECT_HITS[$d]="$keep"
}

check_statamic() {
  local d="$1" root="${APP_ROOT[$1]}" f
  if [ -d "$root/users" ]; then
    f="$(find -L "$root/users" -type f -newerct "$SINCE" -printf '%f\n' 2>/dev/null | grep -v '^\.gitkeep$')"
    if [ -n "$f" ]; then
      add_finding "$d" yellow "Statamic user files changed since $SINCE: $(wc -l <<<"$f") file(s). Check them (names not shown)."
    fi
    APP_NOTES[$d]+="Statamic users (flat files): $(find -L "$root/users" -type f -name '*.yaml' | wc -l)"$'\n'
  else
    APP_NOTES[$d]+="Statamic users are not stored as files. Check the database."$'\n'
  fi
  check_laravel "$d"
}

check_laravel() {
  local d="$1" root="${APP_ROOT[$1]}" dbg size
  dbg="$(grep -E '^APP_DEBUG=' "$root/.env" 2>/dev/null | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')"
  [ "$dbg" = "true" ] && add_finding "$d" yellow "\`APP_DEBUG=true\` in \`.env\`. Set it to false in production."
  size="$(find -L "$root/storage/logs" -type f -name '*.log' -size +500M -printf '%f %s\n' 2>/dev/null)"
  [ -n "$size" ] && add_finding "$d" info "Large Laravel log file(s): $size bytes. Use LOG_CHANNEL=daily."
}

check_matomo() {
  local d="$1" root="${APP_ROOT[$1]}" f
  while read -r f; do
    [ -n "$f" ] || continue
    add_finding "$d" yellow "PHP file in Matomo tmp outside the cache folders: \`${f#"$root"/}\`"
  done < <(find "$root/tmp" -type f -name '*.php' ! -path '*/templates_c/*' ! -path '*/cache/*' \
             ! \( -name index.php -size -100c \) 2>/dev/null)
  APP_NOTES[$d]+="Matomo: run \`console diagnostics:run\` manually for the file integrity check."$'\n'
}

check_exposure() {
  local d="$1" web="${WEB_ROOT[$1]}" f
  [ -n "$web" ] && [ -d "$web" ] || return
  for f in .env phpinfo.php info.php adminer.php dump.php restore.php; do
    while read -r hit; do
      [ -n "$hit" ] || continue
      add_finding "$d" info "Sensitive file in web root: \`${hit#"$web"/}\` (check that it is blocked or remove it)"
    done < <(find "$web" -maxdepth 3 -type f -name "$f" ! -path '*/vendor/*' ! -path '*/wp-admin/*' 2>/dev/null)
  done
  while read -r hit; do
    add_finding "$d" info "World-writable directory: \`${hit#"$web"/}\`"
  done < <(find "$web" -maxdepth 3 -type d -perm -0002 2>/dev/null | head -n 5)
}

# ---------------------------------------------------------------------------
# Step 2c: logs
# ---------------------------------------------------------------------------

check_logs() {
  local d="$1" web="${WEB_ROOT[$1]}" acc err post5 base5 logins p n b sizes path
  local W="$WORK_DIR/${d////_}.window" B="$WORK_DIR/${d////_}.baseline"
  mapfile -t acc < <(ls "$LOG_DIR/$d"-access.log* 2>/dev/null)
  mapfile -t err < <(ls "$LOG_DIR/$d"-error.log* 2>/dev/null)
  [ "${#acc[@]}" -gt 0 ] || { add_finding "$d" info "No access logs found."; return; }

  read_logs "${acc[@]}" | grep -E "$WINDOW_RE" > "$W"
  read_logs "${acc[@]}" | grep -E "$BASELINE_RE" > "$B"

  # Check the log format: field 9 must be a status code.
  if ! awk 'NR<=20 && $9 !~ /^[0-9][0-9][0-9]$/ {bad=1} END {exit bad}' "$W"; then
    add_finding "$d" info "Log format is not the combined format. Log results can be wrong."
  fi

  LOG_POST[$d]="$(awk '$6=="\"POST" {split($7,p,"?"); print $9, p[1]}' "$W" | sort | uniq -c | sort -rn | head -n 12)"

  post5="$(awk '$6=="\"POST" && $9 ~ /^5/' "$W" | grep -c .)"
  base5="$(awk '$6=="\"POST" && $9 ~ /^5/' "$B" | grep -c .)"
  LOG_POST5[$d]="POST 5xx in window: $post5, in the $BASELINE_DAYS days before: $base5"
  if [ "$post5" -gt 10 ] && [ "$post5" -gt $((base5 * 2)) ]; then
    add_finding "$d" yellow "POST 5xx increase: $post5 in window vs. $base5 before. Check paths and sizes:"$'\n'"$(awk '$6=="\"POST" && $9 ~ /^5/ {split($7,p,"?"); print $9, $10, p[1]}' "$W" | sort | uniq -c | sort -rn | head -n 8)"
  fi

  # Status 200 on PHP paths outside the normal entry points.
  while read -r n path; do
    [ -n "$path" ] || continue
    sizes="$(awk -v p="$path" '$9==200 {split($7,q,"?"); if (q[1]==p) print $10}' "$W" | sort -u | tr '\n' ' ')"
    if [ -n "$web" ] && [ -f "$web$path" ]; then
      if [ -n "$(find "$web$path" -newerct "$SINCE" 2>/dev/null)" ]; then
        add_finding "$d" red "Status 200 on \`$path\` ($n x). The file exists and changed in the window."
      else
        add_finding "$d" info "Status 200 on existing file \`$path\` ($n x, bytes: $sizes)"
      fi
    else
      case "$path" in
        */uploads/*|*/assets/*|*/files/*)
          add_finding "$d" yellow "Status 200 on missing PHP file in an upload path \`$path\` ($n x, bytes: $sizes). Soft 404, or a file that was removed after use." ;;
        *) add_finding "$d" info "Status 200 on missing file \`$path\` ($n x, bytes: $sizes). Probably a soft 404." ;;
      esac
    fi
  done < <(awk '$9==200 {split($7,p,"?"); print p[1]}' "$W" | grep -E '\.php$' \
           | grep -vE "$ENTRY_RE" | grep -vE '/v[0-9a-f]{16}\.php$' | sort | uniq -c | sort -rn | head -n 10)

  # Successful logins: POST wp-login.php with 302 (not register, lostpassword or logout).
  logins="$(read_logs "${acc[@]}" | awk '$6=="\"POST" && $9==302 && $7 ~ /^\/wp-login\.php/ && $7 !~ /action=(register|lostpassword|logout|rp|resetpass)/ {print $1, $4}')"
  for b in $TRUSTED_IPS; do logins="$(awk -v ip="$b" '$1 != ip' <<<"$logins")"; done
  if [ -n "$logins" ]; then
    local in_w
    in_w="$(grep -E "$WINDOW_RE" <<<"$logins")"
    if [ -n "$in_w" ]; then
      add_finding "$d" red "Successful WordPress logins in the window from unknown IPs:"$'\n'"$in_w"
    fi
    LOG_LOGINS[$d]="$logins"
  fi

  if [ "${#err[@]}" -gt 0 ]; then
    p="$(read_logs "${err[@]}" | grep -iE 'segfault|exit signal|premature end|end of script output|AH01067' | tail -n 5)"
    [ -n "$p" ] && add_finding "$d" yellow "Possible PHP worker crashes:"$'\n'"$p"
  fi

  n="$(awk '$6=="\"POST" && $7 ~ /xmlrpc\.php/ && $9==200' "$W" | grep -c .)"
  [ "$n" -gt 50 ] && add_finding "$d" info "XML-RPC is open: $n POST requests with status 200 in the window. Block it if nobody uses it."
}

# ---------------------------------------------------------------------------
# Step 2d: account persistence outside the web roots
# ---------------------------------------------------------------------------

# An RCE gives the attacker the rights of the hosting user. Look for persistence that does
# not need a file in the web root. Findings go to the pseudo site "account".
ACCOUNT_NOTES=""

check_account() {
  local a="account" auth keys cron procs prof
  log "Checking the hosting account (SSH keys, cron, processes, profiles)"

  auth="$HOME/.ssh/authorized_keys"
  if [ -f "$auth" ]; then
    keys="$(grep -cE '^(ssh-|ecdsa-|sk-)' "$auth" 2>/dev/null)"
    ACCOUNT_NOTES+="SSH keys in ~/.ssh/authorized_keys: $keys (changed: $(stat -c '%z' "$auth" | cut -c1-19))"$'\n'
    if [ -n "$(find "$auth" -newerct "$SINCE" 2>/dev/null)" ]; then
      # Show fingerprints only. Key comments can contain names and e-mail addresses.
      add_finding "$a" red "\`~/.ssh/authorized_keys\` changed since $SINCE. Fingerprints:"$'\n'"$(ssh-keygen -lf "$auth" 2>/dev/null | awk '{print $1, $2, $NF}')"
    fi
  fi

  cron="$(crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')"
  if [ -n "$cron" ]; then
    ACCOUNT_NOTES+="Cron jobs (check that you know each one):"$'\n'"$cron"$'\n'
    if grep -qiE 'curl|wget|base64|/tmp/|/dev/shm/|nc[[:space:]]|bash[[:space:]]+-i|python|perl[[:space:]]+-e' <<<"$cron"; then
      add_finding "$a" yellow "Cron job with a download, decode or shell pattern. Check the cron list below."
    fi
  fi

  # Processes of this user, without this script and its children.
  procs="$(ps -u "$(id -u)" -o pid=,ppid=,etime=,args= 2>/dev/null \
           | awk -v me="$$" '$1 != me && $2 != me' \
           | grep -E '/tmp/|/dev/shm/|base64|bash[[:space:]]+-i|nc[[:space:]]+-|socat|xmrig|minerd|php[^ ]*[[:space:]]+-S[[:space:]]' \
           | grep -v 'grep -E')"
  [ -n "$procs" ] && add_finding "$a" yellow "Suspect running processes:"$'\n'"$procs"

  # Shell profiles and other files in the home directory that changed in the window.
  prof="$(find "$HOME" -maxdepth 2 -type f -newerct "$SINCE" \
            ! -path "$HOME/.bash_history" ! -path "$HOME/.lesshst" ! -path "$HOME/.viminfo" \
            ! -path "$HOME/.cache/*" ! -path "$HOME/.wp-cli/*" ! -path "$DATA_DIR/*" \
            ! -path "$HTML_DIR/*" ! -path "$LOG_DIR/*" ! -path "$HOME/webstats/*" \
            -printf '%CY-%Cm-%Cd %CH:%CM  %p\n' 2>/dev/null | sed "s#  $HOME/#  ~/#" | sort)"
  if [ -n "$prof" ]; then
    if grep -qE '~/\.(bashrc|bash_profile|bash_login|bash_logout|profile|zshrc)$' <<<"$prof"; then
      add_finding "$a" red "Shell profile changed since $SINCE:"$'\n'"$prof"
    elif grep -qE '~/(\.config|etc)/' <<<"$prof"; then
      add_finding "$a" yellow "Config or service file changed since $SINCE (check it):"$'\n'"$prof"
    else
      add_finding "$a" info "Files in the home directory changed since $SINCE:"$'\n'"$prof"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

declare -A CHANGED_COUNT=() CHANGED_GROUPS=() SUSPECT_HITS=() DIR_CHANGES=() APP_NOTES=() \
           PLUGINS_FAILED=() PLUGINS_SKIPPED=() LOG_POST=() LOG_POST5=() LOG_LOGINS=()

# Find the web root and log directories if the operator did not set them.
first_dir() { local x; for x in "$@"; do [ -d "$x" ] && { echo "$x"; return; }; done; }
[ -n "$HTML_DIR" ] || HTML_DIR="$(first_dir "$HOME/html" "$HOME/public_html" "$HOME/httpdocs" "$HOME/www" "$HOME/htdocs")"
[ -n "$LOG_DIR" ] || LOG_DIR="$(first_dir "$HOME/logs" "$HOME/log" "$HOME/access-logs")"
[ -n "$HTML_DIR" ] && [ -d "$HTML_DIR" ] || { echo "Error: no web root directory found. Use --html DIR." >&2; exit 2; }
[ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ] || { echo "Error: no log directory found. Use --logs DIR." >&2; exit 2; }
log "Web roots: $HTML_DIR, logs: $LOG_DIR"

START_TS="$(date -u '+%F %H:%M UTC')"
log "Window: $SINCE until $TODAY"
discover_sites
log "Sites: ${DOMAINS[*]}"

check_php_cli
[ "$MEASURE_PHP" = 1 ] && check_php_web

for d in "${DOMAINS[@]}"; do
  log "Checking $d (${APP[$d]})"
  if [ -z "${APP_ROOT[$d]}" ]; then
    add_finding "$d" info "No application root found. Use --site $d=PATH."
    check_logs "$d"
    continue
  fi
  check_filesystem "$d"
  case "${APP[$d]}" in
    wordpress) check_wordpress "$d" ;;
    statamic) check_statamic "$d" ;;
    laravel) check_laravel "$d" ;;
    matomo) check_matomo "$d" ;;
  esac
  # Report suspect-code hits in plugins and themes as one line per component, other hits per file.
  while read -r n comp; do
    [ -n "$comp" ] || continue
    case "$comp" in
      wp-content/plugins/*|wp-content/themes/*)
        add_finding "$d" yellow "$n changed PHP file(s) with suspect code in \`$comp\`. If this is an update, \`--wp-cli\` checksums confirm it." ;;
      *) add_finding "$d" yellow "PHP file with suspect code: \`$comp\`" ;;
    esac
  done < <(while IFS= read -r f; do [ -n "$f" ] && printf '%s\n' "${f#"${APP_ROOT[$d]}"/}"; done <<<"${SUSPECT_HITS[$d]:-}" \
           | awk -F/ '{ if ($1=="wp-content" && ($2=="plugins" || $2=="themes") && NF>3) print $1"/"$2"/"$3; else print $0 }' \
           | sort | uniq -c)
  check_exposure "$d"
  check_logs "$d"
done

check_account

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

# Print the findings of one key (site or "account"), grouped by severity.
print_findings() {
  local f="${FINDINGS[$1]:-}" sev blk
  for sev in red yellow info; do
    blk="$(awk -v s="$sev" '
      /^(red|yellow|info)\|/ { cur = substr($0, 1, index($0, "|") - 1); txt = substr($0, index($0, "|") + 1);
                               if (cur == s) { print "- " txt } ; next }
      { if (cur == s && $0 != "") print "  " $0 }' <<<"$f")"
    if [ -n "$blk" ]; then
      echo "**$sev**"
      echo
      printf '%s\n\n' "$blk"
    fi
  done
}

worst="green"
for d in "${DOMAINS[@]}" account; do
  case "$(site_status "$d")" in
    red) worst="red" ;;
    yellow) [ "$worst" = green ] && worst="yellow" ;;
  esac
done

cat <<EOF
# PHP2Shell check report

- Host: \`$(hostname 2>/dev/null || echo unknown)\`
- Run: $START_TS
- Window: $SINCE until $TODAY (baseline: $BASELINE_DAYS days before)
- Script: wp-php2shell-check $VERSION

## Result

EOF
case "$worst" in
  green) echo "No signs of a PHP2Shell exploit or of a compromise. Read the hints below for hardening." ;;
  yellow) echo "No clear signs of a compromise, but some items need a manual review (yellow)." ;;
  red) echo "**At least one red criterion. Stop, preserve evidence (\`cp -p\`, \`sha256sum\`) and review the items below before you change anything.**" ;;
esac

echo
echo "## PHP versions"
echo
if [ -n "$PHP_WEB_TABLE" ]; then
  echo "Web (measured over HTTP):"
  echo
  echo "| Domain | Version | Status | session.upload_progress |"
  echo "|---|---|---|---|"
  printf '%s' "$PHP_WEB_TABLE"
  echo
else
  echo "Web version not measured (use \`--measure-php\`). The CLI version can differ from the web version."
  echo
fi
if [ -n "$PHP_CLI_TABLE" ]; then
  echo "CLI binaries:"
  echo
  echo "| Binary | Version | Status |"
  echo "|---|---|---|"
  printf '%s' "$PHP_CLI_TABLE"
  if [ -n "$PHP_CLI_OLD" ]; then
    echo
    echo "$PHP_CLI_OLD"
  fi
  echo
fi

echo "## Overview"
echo
echo "| Domain | App | Version | Changed files | Status |"
echo "|---|---|---|---|---|"
for d in "${DOMAINS[@]}"; do
  v="-"; [ -n "${APP_ROOT[$d]}" ] && v="$(app_version "${APP_ROOT[$d]}" "${APP[$d]}")"
  echo "| $d | ${APP[$d]} | $v | ${CHANGED_COUNT[$d]:-0} | $(site_status "$d") |"
done
echo

echo "## Details per site"
for d in "${DOMAINS[@]}"; do
  echo
  echo "### $d ($(site_status "$d"))"
  echo
  echo "- App root: \`${APP_ROOT[$d]:-unknown}\`"
  echo "- Web root: \`${WEB_ROOT[$d]:-unknown}\`"
  echo
  print_findings "$d"
  if [ -n "${CHANGED_GROUPS[$d]:-}" ]; then
    echo "Changed files since $SINCE (count, date, time, component). Big blocks at the same minute are usually updates:"
    echo
    md_code "$(head -n 30 <<<"${CHANGED_GROUPS[$d]}")"
    echo
  fi
  if [ -n "${DIR_CHANGES[$d]:-}" ]; then
    echo "Directory changes (no new files: often the WP-cron write test, compare with the wp-cron hits in the access log):"
    echo
    md_code "$(head -n 15 <<<"${DIR_CHANGES[$d]}")"
    echo
  fi
  if [ -n "${APP_NOTES[$d]:-}" ]; then
    echo "Application:"
    echo
    md_code "${APP_NOTES[$d]}"
    echo
  fi
  if [ -n "${LOG_POST[$d]:-}" ]; then
    echo "POST requests in the window (count, status, path):"
    echo
    md_code "${LOG_POST[$d]}"
    echo
  fi
  [ -n "${LOG_POST5[$d]:-}" ] && echo "- ${LOG_POST5[$d]}"
  if [ -n "${LOG_LOGINS[$d]:-}" ]; then
    echo "- Successful WordPress logins in the available logs (IP, time):"
    echo
    md_code "${LOG_LOGINS[$d]}"
  fi
done

echo
echo "## Hosting account ($(site_status account))"
echo
echo "SSH keys, cron jobs, running processes and files in the home directory (outside the web roots)."
echo
print_findings account
if [ -n "$ACCOUNT_NOTES" ]; then
  md_code "$ACCOUNT_NOTES"
  echo
fi

cat <<'EOF'

## Known noise

These patterns alone are not a finding:

- `wp-content/uploads/pageviews.php` that starts with `<?php exit; ?>` followed by `p,...` lines: Koko Analytics buffer.
- Directory changes of the WordPress root, `plugins/` and `themes/` within seconds after a `wp-cron.php` hit and no new files: WordPress write test.
- POST 500 on `/wp-json/batch/v1` with constant size on WordPress 6.4: core bug `WP_Error::get_method()`, triggered by scanners.
- Status 200 on PHP files that do not exist, with constant byte size: soft 404 (theme or maintenance plugin).
- POST `wp-login.php?action=register` with 302 to `registration=disabled`: refused registration, not a login.

## Limits

This script supports a manual check. It does not replace a forensic analysis. A clean report does not prove that a site is not compromised. Attackers can hide in the database, in premium plugins without checksums or outside the checked paths.
EOF
