# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability in this scanner. Email the
maintainer instead and allow reasonable time for a fix before disclosure.

## Reporting a false positive

False positives matter more here than in most tools. This scanner sits next to a
**Quarantine** button, and a wrong answer can take a working site offline.

If a scan flags a file you believe is clean, please open an issue using the
**False positive** template. Include the finding's source layer (Core integrity,
Baseline drift, Structural, or AMWScan), the file path relative to the site root,
and the platform. If you can share the file, that is ideal - but never paste
credentials, and never attach `wp-config.php`.

## Reporting a miss

The opposite case is just as useful. If this scanner said clean and the site was
not, tell us what it missed and, if you can, how the payload was constructed.

## What this tool does not do

It does not phone home, transmit findings anywhere, or upload your files. The
only outbound request it makes is to `api.wordpress.org` to fetch official
WordPress core checksums. Disable that by blocking the host; the scan continues
with the remaining layers and says plainly that core verification did not run.
