# GTS Scanner

A browser dashboard for [AMWScan](https://github.com/marcocesarato/PHP-Antimalware-Scanner),
plus baseline drift detection for code that no upstream can vouch for.

Single PHP file. No dependencies.

## Read this before you install

**AMWScan already covers most of what you probably want.** It has an official
[WordPress plugin](https://wordpress.org/plugins/amwscan) with a dashboard,
background scans, quarantine and reports. It also does integrity verification
against trusted release checksums for WordPress, WooCommerce, Drupal, Joomla,
Magento, PrestaShop, TYPO3, Laravel, Symfony, CodeIgniter, Yii and CakePHP.

**If you are on WordPress, install their plugin instead.** It is more mature and
better maintained than this.

This project exists for a narrower gap.

## The gap it fills

**1. A browser UI for PHP projects that are not WordPress.**
AMWScan's dashboard is a WordPress plugin. Everywhere else it is CLI only. On
shared hosting with cPanel and no SSH, that is a problem. This gives you a login,
a scan button, severity-ranked findings, quarantine and restore — in a browser.

**2. Baseline drift for code with no upstream.**
AMWScan compares your files against *official release checksums*. That works
brilliantly for WordPress core and Composer packages, and not at all for a
bespoke theme, a client's custom plugin, or an application written in-house —
because nobody publishes hashes for those.

This records a SHA-256 of **every file in your tree** at a moment you choose,
then reports what was added, changed or removed since. It cannot tell you a file
is *correct*, only that it is *different from when you last looked*. For custom
code, that is usually the question worth asking.

It is also what catches a backdoor that keeps rewriting itself — the file
reappears as *added* on the next scan.

Capture the baseline while the site is clean. A baseline taken from a
compromised site makes the compromise look normal.

## Install

1. Copy `securityscanner.php` to your web root
2. Open `https://your-site/securityscanner.php` and set a password (12 characters minimum)
3. Click **Install AMWScan** — your server downloads the current release straight
   from the [upstream project](https://github.com/marcocesarato/PHP-Antimalware-Scanner).
   The download is checked before it is used and test-run before it is put in place.
4. Point the scan path at your project, **capture a baseline**, and scan

That's it. No command line.

AMWScan is never shipped in this repository — it is GPL-3.0, and downloading it
from upstream keeps it that way while giving you the current release rather than
a frozen copy. If your server has no outbound internet access, the dashboard tells
you where to download it by hand.

**Auto-quarantine is off by default.** AMWScan's signatures do produce false
positives — in testing it flagged a one-line `<?php echo "hello";` file — and an
automatic move can take a working site down. Review findings, then quarantine.
Turn auto-quarantine on in Scan Configuration once you trust the results on that
host.

Remove the file or restrict access when you are done. It is an authenticated
admin tool; do not leave it on a public server longer than you need it.

## Requirements

| | |
|---|---|
| PHP | 7.4+ with `exec()` enabled |
| PHP CLI | Needed for the AMWScan layer. Auto-detected across cPanel, CloudLinux, LiteSpeed, Plesk, XAMPP, WAMP, Laragon — Linux and Windows |
| Network | Only for WordPress core checksums. Baseline drift works fully offline |
| Dependencies | None |

If a scan will not start, open **Server Diagnostics** — it lists the PHP CLI
binary in use and every path tried.

## It will never claim more than it checked

Every scan reports what did **not** run. If PHP CLI is missing, the baseline and
structural layers still run and the dashboard says the malware scan did not. If
nothing ran, the scan fails loudly rather than reporting "clean".

## What it does

| Layer | Applies to | Deterministic |
|---|---|---|
| Baseline drift | Any PHP project | Yes |
| Structural rules | Any PHP project | Yes |
| WordPress core checksums | WordPress | Yes |
| AMWScan signatures | Any PHP project | No — pattern matching |

Structural rules: a PHP file inside an upload directory, PHP code inside a file
with an image extension, and WordPress must-use plugins.

## Measured

Against a real WordPress 7.0.3 install (3,945 files):

| | Result |
|---|---|
| Baseline capture | 3,078 files hashed in 3.7s |
| Drift re-run, nothing changed | **0 false drift** |
| Structural rules, clean install | **0 findings** |
| Core verification, clean install | **3,496 files verified** |
| Simulated infection, 7 artefacts | **all 7 detected** |

End-to-end integration verified against **AMWScan 0.21.2**.

## Known limitations

- **Not tested against a large third-party plugin corpus.** Validated against
  stock WordPress and a generic PHP project.
- **Baseline drift reports change, not badness.** A legitimate plugin update
  shows as dozens of modified files. Re-capture after updates.
- **A plugin that arrives already trojanised**, on a site that never had a clean
  baseline, is caught only if AMWScan's signatures catch it.
- **Stop cannot interrupt a foreground scan** mid-file.
- **The `api.wordpress.org` fetch is unproven against the live endpoint** — the
  comparison logic was validated against a checksum map in the API's exact shape.

## Credits

Malware detection is [AMWScan](https://github.com/marcocesarato/PHP-Antimalware-Scanner)
by Marco Cesarato, GPL-3.0. This is a companion to it, not a replacement, and it
is the more capable tool. Use it directly wherever you can.

## Licence

MIT — see [LICENSE](LICENSE). Read [LICENSING.md](LICENSING.md) before bundling
or selling; AMWScan is GPL-3.0 and is deliberately not included here.
