# Changelog

## 3.2.0

Plug and play.

- **One-click AMWScan install.** When AMWScan is missing, the dashboard offers an
  **Install AMWScan** button. The server downloads the current release from the
  upstream project, rejects anything that is not recognisably the AMWScan phar,
  test-runs it, and only then moves it into place. AMWScan is still never
  distributed by this project.
- **A missing AMWScan no longer blocks the scan.** Baseline drift and the
  structural rules run anyway, and the dashboard says the signature scan did not.
- **Fixed: clean AMWScan scans were reported as "did not run".** Completion was
  detected only from a `100%` progress frame, which AMWScan often never writes on
  small or fast scans. It now uses AMWScan's own `Scan finished!` and summary
  lines. On a healthy site this bug would have hidden every clean result.
- **Auto-quarantine now defaults to off.** In testing, AMWScan flagged a one-line
  `<?php echo "hello";` file as malware and moved it automatically. A signature
  false positive must never move a live file without a human deciding.


## 3.1.1

Corrected the project's positioning after re-reading AMWScan's current
documentation, and fixed the AMWScan integration for current releases.

- **AMWScan has an official WordPress plugin and its own integrity verification.**
  Earlier versions of this README claimed otherwise. Both claims were wrong. The
  README now states plainly that WordPress users should install AMWScan's plugin
  instead, and narrows this project's claim to the two things that are actually
  distinct: a browser UI for non-WordPress PHP, and baseline drift over code with
  no upstream checksums.
- **AMWScan now ships as `scanner`, a phar, not `scanner.php`.** The lookup
  accepts `scanner`, `scanner.php`, `amwscan`, `amwscan.phar` and the Composer
  paths. Install instructions corrected to `dist/scanner`.
- Verified end-to-end against real AMWScan 0.21.2 for the first time — all
  planted backdoors detected, log parsing and finding merge both correct.


## 3.1.0

Integrity layers no longer require WordPress.

- **Baseline drift now runs on any PHP project.** It is SHA-256 hashing; gating
  it behind WordPress detection was an arbitrary limitation. It now covers
  Laravel, Magento, custom applications and `vendor/` directories.
- **Structural rules generalised.** "PHP in `wp-content/uploads`" became "PHP in
  any upload directory" (`uploads`, `upload`, `attachments`, `userfiles`,
  `user-uploads`); "PHP inside an image" now applies across the whole tree.
- Core checksum verification remains WordPress-only, and says so, because no
  authority publishes hashes for an arbitrary PHP application.
- A missing PHP CLI is fatal only when the scan path is unreadable as well.

Verified: on a non-WordPress PHP project, structural rules and baseline drift
both fire correctly and core verification reports "not applicable". WordPress
behaviour is unchanged - same 3,496 core files verified, same infection caught.

## 3.0.0

Integrity verification added. Detection stopped depending on guessing.

- **Core integrity** against official `api.wordpress.org` checksums, cached 30
  days, hash algorithm detected per entry
- **Baseline drift** - a local SHA-256 manifest covering plugins and themes
- **Structural rules** - PHP in uploads, PHP inside images, must-use plugins
- Every scan reports what did **not** run; a scan where nothing ran fails loudly
- Any scan failure records a reason instead of leaving the dashboard on "running"

Measured on real WordPress 7.0.3: 0 false drift over 3,078 files, 0 structural
findings on a clean install, 3,496 core files verified, and all 7 artefacts of a
simulated infection detected.

## 2.5.0

Removed the custom signature engine. AMWScan only.

The engine was flagging untouched WordPress files. It was rewritten in 2.4.2 and
measured clean against everything available at the time, but was removed rather
than ship a second engine that had already been wrong twice in the field.

PHP CLI became a hard requirement. A scan without it fails loudly rather than
reporting "clean" about an unexamined site.

## 2.4.2

Signature engine rewritten after it was found flagging WordPress core.

Root causes: `.*?` with the `/s` modifier spans a whole file, so a `$_SERVER` on
line 3 paired with `wp_filesystem` hundreds of lines later; and missing word
boundaries meant `system` matched inside `wp_filesystem` and `.exec(` - the
standard JavaScript regex method - looked like a shell call.

Measured against 1,060 real WordPress JS files: **3.6% false positives before,
0% after**, including 12.7% of jQuery's own files before the fix.

Later measured against real WordPress core PHP: **1 file in 3,033 (0.03%)**, and
that one match was on a commented-out line.

## 2.4.1

Eleven bugs found by testing rather than reading, including an obfuscated-eval
regex that never compiled, signature findings that could not be quarantined, and
PHP CLI auto-detection that was dead code on foreground scans.

## 2.4.0

Dual-engine detection. Superseded.
