
<h1 align="center">wp-php2shell-check</h1>

<p align="center">
  <strong>Was your WordPress site hit by PHP2Shell before the patch?</strong><br>
  One read-only Bash script. One SSH command. One clear report: green, yellow or red.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/shell-bash-4EAA25?logo=gnubash&logoColor=white" alt="Bash">
  <img src="https://img.shields.io/badge/WordPress-shared%20hosting-21759B?logo=wordpress&logoColor=white" alt="WordPress">
  <img src="https://img.shields.io/badge/CVE-2026--109618%20%7C%20109619-critical" alt="CVE-2026-109618 and CVE-2026-109619">
  <img src="https://img.shields.io/badge/mode-read--only-blue" alt="Read-only">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-checks">What it checks</a> ·
  <a href="#known-noise">Known noise</a> ·
  <a href="#if-the-report-is-red">If the report is red</a> ·
  <a href="#deutsch">Deutsch</a>
</p>

---

## Quick start

```bash
curl -O https://raw.githubusercontent.com/digital-heroes-hamburg/wp-php2shell-check/main/wp-php2shell-check.sh

ssh user@host.example 'bash -s -- --measure-php --wp-cli' < wp-php2shell-check.sh > report.md
```

The script runs **on the webspace**, writes a Markdown report to your machine and leaves nothing behind. Add `-p PORT` to `ssh` if your host uses another SSH port.

## Why

**PHP2Shell** (CVE-2026-109618 / CVE-2026-109619) is an unauthenticated remote code execution in PHP ≥ 5.4. The details leaked on 20 October 2026, attacks started the next morning, and the patch came that afternoon. Hosting providers rolled it out fast, but not instantly.

If you look after WordPress sites on shared hosting, two questions remain:

1. **Is the web server on a patched PHP build?** The CLI binary can differ from the web build.
2. **Did anybody use the gap before the patch?**

We answered both by hand for our hosting clients. This script is that work, automated, plus the list of false alarms that cost us the most time.

## What it checks

| Area | Checks |
|---|---|
| **PHP patch level** | Web PHP measured over HTTP, including `session.upload_progress.enabled` (PHP recommends 0 until the next release, CVE-2026-115560). All `php-8.x` CLI binaries. Fixed in **8.5.12, 8.4.27, 8.3.36, 8.2.35**. 8.1 and older get no fix. |
| **File system** | Files with a changed **ctime** since the leak (an attacker cannot set ctime back), grouped by component and minute so that updates stand out. Suspect code (`eval`, `base64_decode`, `gzinflate`, superglobal calls, …, case-insensitive) in changed `.php`, `.phtml`, `.phar` and `.inc` files, and in **all** PHP files in the WordPress root and in `mu-plugins`. Hidden and double-extension PHP. PHP in `uploads`. `auto_prepend_file` and PHP handlers in any `.user.ini` or `.htaccess`. |
| **Hosting account** | An RCE runs as the hosting user, so the script also looks outside the web roots: changes to `~/.ssh/authorized_keys` (fingerprints only), cron jobs, suspect running processes, changed shell profiles and config files in the home directory. |
| **WordPress** | Core and plugin checksums, administrators, users registered since the leak, available updates (with `--wp-cli`). Suspect-code hits in plugins that pass the checksum check are dropped as noise. |
| **Logs** | POST requests per status and path, POST 5xx compared with the days before the leak, status 200 on unusual PHP paths (with file check and byte sizes), successful logins, PHP worker crashes. |
| **Hardening hints** | World-writable `wp-config.php`, `wp-file-manager`, exposed tools (`adminer.php`, `phpinfo.php`, MySQLDumper), `.env` in the web root, open XML-RPC. |

Statamic, Laravel and Matomo installations on the same webspace get basic checks too.

## Example report

<details>
<summary>Show a shortened report (fake data)</summary>

```markdown
## Result

**At least one red criterion. Stop, preserve evidence (`cp -p`, `sha256sum`) and review the items below before you change anything.**

## PHP versions

| Domain           | Version | Status            |
|------------------|---------|-------------------|
| example.com      | 8.3.36  | ok (fix: 8.3.36)  |

## Overview

| Domain           | App       | Version | Changed files | Status |
|------------------|-----------|---------|---------------|--------|
| example.com      | wordpress | 7.1.3   | 1406          | green  |
| shop.example.org | wordpress | 6.4.3   | 3             | yellow |
| old.example.net  | wordpress | 6.2     | 2             | red    |

### old.example.net (red)

**red**
- PHP file in upload folder: `wp-content/uploads/2026/10/cache.php` (sha256 6271eff59aa1d15f...)
- Status 200 on `/wp-content/uploads/2026/10/cache.php` (3 x). The file exists and changed in the window.

**info**
- Koko Analytics buffer in uploads (normal): `wp-content/uploads/pageviews.php`
- Status 200 on missing file `/222.php` (12 x, bytes: 832). Probably a soft 404.
```

</details>

## Status levels

| Status | Meaning | Examples |
|---|---|---|
| **red** | Stop and preserve evidence | PHP file in `uploads`, `auto_prepend_file` in a `.user.ini`, failed core checksums, new admin since the leak, login from an unknown IP, changed `authorized_keys` or shell profile, unpatched web PHP |
| **yellow** | Review manually | Suspect code in a changed file, plugin checksum mismatch, POST 5xx spike, `wp-config.php` world-writable |
| **green** | No signs of a compromise | Only known noise and hardening hints |

## Options

| Option | Meaning |
|---|---|
| `--since YYYY-MM-DD` | Start of the time window (default: `2026-10-20`, the day of the leak) |
| `--measure-php` | Puts a PHP file with a random name in each web root, requests it over HTTPS (PHP version and `session.upload_progress.enabled`) and deletes it at once |
| `--wp-cli` | Gets `wp-cli.phar` if it is missing, runs it with `--skip-plugins --skip-themes` and deletes it at the end |
| `--keep-wpcli` | Keeps `wp-cli.phar` |
| `--php BIN` | PHP binary for WP-CLI (default: newest `php-8.x`). Some hosts ask interactively for a version if you call plain `php`. |
| `--trusted-ip IP` | IP whose logins you expect, for example your office (repeat as necessary) |
| `--site DOMAIN=PATH` | Sets the application root if auto-detection fails, for example WordPress in a subfolder |
| `--html DIR`, `--logs DIR` | Other locations for web roots and logs |

**Layout.** The script looks for web roots in `~/html`, `~/public_html`, `~/httpdocs`, `~/www` or `~/htdocs`, and for logs in `~/logs`, `~/log` or `~/access-logs`. Logs must be in the combined format and named `<domain>-access.log*`. One site directly in `~/public_html` works too. Tested on hosting.de. On other hosts, `--html`, `--logs` and `--site` cover most layouts. If yours does not work, please [open an issue](https://github.com/digital-heroes-hamburg/wp-php2shell-check/issues).

**Footprint.** Without options the script only reads in your web roots. It keeps log extracts in a private temp directory (`mktemp`) instead of memory. `--measure-php` and `--wp-cli` write temporary files and remove them, also if you stop the script with Ctrl+C. `wp-cli.phar` is checked against its published SHA-512 before use. It never prints the content of `wp-config.php` or `.env`, and never prints e-mail addresses of users.

## Known noise

The false alarms we saw on real webspaces. The script knows them and reports them as `info`:

| Looks like | Actually is |
|---|---|
| `wp-content/uploads/pageviews.php` | Buffer of **Koko Analytics**: `<?php exit; ?>` followed by lines like `p,137,1,1,https://…` |
| WordPress root, `plugins/` and `themes/` change in the same second, but no file is new | WordPress **write test** (`get_filesystem_method()`), started by `wp-cron.php` a second before |
| Many POST 500 on `/wp-json/batch/v1`, all with the same size | Core bug in **WordPress 6.4** (`WP_Error::get_method()`), triggered by scanners, also before the leak |
| Status 200 on `/222.php`, `/wp-config.php.bak`, … | **Soft 404** from a maintenance or coming-soon plugin. The files do not exist. |
| POST `wp-login.php?action=register` with 302 | Refused registration (`registration=disabled`), not a login |
| `hello.php` fails the plugin checksum | Hello Dolly variant that ships with WordPress core |

## If the report is red

1. **Stop.** Do not delete or "clean" anything yet.
2. **Preserve evidence** with timestamps: `mkdir -p ~/data/forensik-$(date +%F) && cp -p FILE ~/data/forensik-$(date +%F)/`
3. **Write down the hash:** `sha256sum FILE`
4. **Inform your hosting provider.** If personal data can be affected, check your GDPR duties: Art. 33 GDPR gives you **72 hours** to notify the authority.

## Limits

This script **supports** a manual check. It does **not** replace a forensic analysis. A green report does not prove that a site is clean: attackers can hide in the database, in premium plugins without public checksums, in the theme or outside the checked paths.

## License

[MIT](LICENSE). No warranty. Use at your own risk.

## About

Built by **[Digital Heroes GmbH](https://digital-heroes.co)**, a web agency in Hamburg, Germany. We host and look after WordPress and Laravel sites, mainly on German infrastructure.

Need help with a check or a cleanup? [Get in touch](https://digital-heroes.co).

---

## Deutsch

**`wp-php2shell-check`** prüft WordPress-Websites auf Shared Hosting nach der PHP-Lücke **PHP2Shell** (CVE-2026-109618/-109619). Das Skript arbeitet nur lesend und liefert einen Markdown-Bericht mit grÃ¼n, gelb oder rot pro Website. Es prüft:

- ob der Webserver eine gepatchte PHP-Version nutzt
- ob sich seit dem Leak Dateien geändert haben (ctime)
- ob Core und Plugins zu den Checksummen passen
- ob neue Admins oder erfolgreiche Logins in den Logs auftauchen

```bash
ssh user@host.example 'bash -s -- --measure-php --wp-cli' < wp-php2shell-check.sh > bericht.md
```

Die typischen Fehlalarme (Koko Analytics, wp-cron-Schreibtest, WP-6.4-Batch-Bug, Soft-404) stehen oben unter [Known noise](#known-noise).

Ein grüner Bericht ist **kein** Beweis, dass eine Website sauber ist. Bei Rot zuerst Beweise sichern, dann handeln. Sind personenbezogene Daten betroffen, gilt die DSGVO-Meldefrist von 72 Stunden.

Hilfe bei der Prüfung oder Bereinigung: **[Digital Heroes GmbH, Hamburg](https://digital-heroes.co)**
