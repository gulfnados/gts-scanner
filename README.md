# GTS Scanner

A single-file web dashboard and **integrity layer** for PHP malware scanning.
Drop one file on a server, open it in a browser, and get file-integrity
verification plus a UI around [AMWScan](https://github.com/marcocesarato/PHP-Antimalware-Scanner).

Works on WordPress and on any other PHP project.

![Dashboard](docs/dashboard.png)

## What this is, and what it is not

**This is not another malware scanner.** Signature detection is AMWScan's job and
it already does it well. This project adds the two things AMWScan does not:

- **Integrity verification** - comparing files against known-good hashes rather
  than guessing whether code looks dangerous
- **A web dashboard** - so a client who will never open a terminal can run a
  scan, see severity-ranked findings, quarantine a file, and restore it

If you want a CLI scanner, use AMWScan directly. If you want to hand a
non-technical site owner something they can actually use, this is that.

## How detection works

Three layers. Two of them involve no guessing at all.

### 1. Core integrity — deterministic, WordPress only

Reads the installed version, fetches official checksums from `api.wordpress.org`,
and compares every core file. Reports **modified core file**, **unknown file
inside a core directory** (where dropped shells live), and **missing core file**.

This is a hash comparison. It does not produce false positives.

### 2. Baseline drift — deterministic, any PHP project

Records a SHA-256 of every source file. Later scans report what was **added**,
**changed** or **removed** since.

This is the layer that covers plugins, themes, `vendor/` directories and your own
application code — everything no upstream authority publishes hashes for. It is
also what catches a backdoor that keeps rewriting itself: the file reappears as
*added* on the next scan.

Capture the baseline while the site is clean. A baseline taken from a compromised
site makes the compromise look normal.

### 3. AMWScan — signatures

Pattern-based malware detection, run as a separate CLI process. Requires PHP CLI.
Not bundled — see [LICENSING.md](LICENSING.md).

Structural rules run alongside: a PHP file inside an upload directory, PHP code
inside a file with an image extension, and WordPress must-use plugins.

## It will never claim more than it checked

Every scan reports what **did not** run. If PHP CLI is missing, the integrity
layers still run and the dashboard says the malware scan did not. If nothing ran,
the scan fails loudly rather than reporting "clean".

A security tool that says clean about something it never examined is worse than
no tool at all.

## Install

```bash
# 1. Get AMWScan (separate GPL-3.0 project — do not commit it to a fork)
wget https://github.com/marcocesarato/PHP-Antimalware-Scanner/releases/latest/download/scanner.php

# 2. Put both files in your web root
cp scanner.php securityscanner.php /var/www/html/
```

Then open `https://your-site/securityscanner.php`, set a password (12 characters
minimum), point the scan path at your project root, **capture a baseline**, and
scan.

Delete or move `securityscanner.php` when you are finished, or restrict access to
it. It is an authenticated admin tool; do not leave it on a public server longer
than you need it.

## Requirements

| | |
|---|---|
| PHP | 7.4+ with `exec()` enabled |
| PHP CLI | Required for the AMWScan layer only. Auto-detected across cPanel, CloudLinux, LiteSpeed, Plesk, XAMPP, WAMP and Laragon on Linux and Windows |
| Network | Outbound HTTPS to `api.wordpress.org` for core checksums. Everything else works offline |
| Dependencies | None |

If a scan will not start, open the **Server Diagnostics** panel — it lists the
PHP CLI binary in use and every path that was tried.

## Measured results

Against a real WordPress 7.0.3 install (3,945 files):

| | Result |
|---|---|
| Baseline capture | 3,078 files hashed in 3.7s |
| Drift re-run, nothing changed | **0 false drift** |
| Structural rules, clean install | **0 findings** |
| Core verification, clean install | **3,496 files verified** |
| Simulated infection, 7 artefacts planted | **all 7 detected** |

## Known limitations

Stated plainly, because a security tool that oversells itself is dangerous:

- **Not tested against a large third-party plugin corpus.** Validated against
  stock WordPress and a generic PHP project. Integrity checking is unaffected by
  this — it is hash comparison — but it is why there is no bundled signature
  engine of our own.
- **The `api.wordpress.org` fetch is unproven against the live endpoint.** The
  comparison logic was validated against a checksum map in the exact shape the
  API returns. Check the Integrity panel on your first install.
- **A plugin that arrives already trojanised**, on a site that never had a clean
  baseline, is caught only if AMWScan's signatures catch it.
- **Stop cannot interrupt a foreground scan** mid-file; it takes effect when the
  current step finishes.

## Credits

Malware signature detection by [AMWScan](https://github.com/marcocesarato/PHP-Antimalware-Scanner)
(Marco Cesarato), GPL-3.0. This project is a companion to it, not a replacement.

## Licence

MIT — see [LICENSE](LICENSE). Read [LICENSING.md](LICENSING.md) before bundling
or selling anything built on this; AMWScan is GPL-3.0 and is deliberately not
included here.
