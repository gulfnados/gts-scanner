# Contributing

## The one rule that matters

**Every detection change ships with a measurement.**

This project removed its own signature engine once, and rewrote it twice, because
rules were added on the strength of "this looks like it should work". A rule that
has not been measured against real third-party code does not go in.

A detection PR must state:

- what it detects, with a sample that triggers it
- what it was measured against, and the false-positive count on that corpus
- why the rule cannot match ordinary framework or library code

"Measured against real code" means real WordPress core, real plugins, real
vendor directories - not hand-written examples. Hand-written clean samples are
how this project shipped a 3.6% false-positive rate while believing it was zero.

## Corpora worth testing against

- WordPress core (any recent version)
- jQuery, TinyMCE, and other minified libraries WordPress ships
- A real site's `wp-content` with its actual plugin set
- Laravel, Magento, or any large PHP application with a `vendor/` directory

## Two failure modes that keep recurring

1. **`.*?` with the `/s` modifier spans the whole file.** A superglobal on line 3
   will pair with a keyword 400 lines later. Bound your distance.
2. **Missing word boundaries.** Without `\b`, `system` matches inside
   `wp_filesystem`, `eval` inside `evaluate`, and `exec` inside `.exec(` - which
   is the standard JavaScript regex method.

## Do not commit

- `scanner` / `scanner.php` (AMWScan - separate GPL-3.0 project, see `LICENSING.md`)
- Any real site's files, baseline, or `wp-config.php`
- Scan output, reports, or quarantine contents

## Code style

Single file, no dependencies, PHP 7.4 compatible. That constraint is the product:
it is what lets someone drop one file onto a shared host and get a dashboard.
Keep it.
