# Licensing and the relationship to AMWScan

**Read this before you bundle, fork, or sell anything built on this project.**

## This project

`securityscanner.php` is MIT licensed. See `LICENSE`.

## AMWScan is a separate project under a different licence

The malware-signature layer is [AMWScan](https://github.com/marcocesarato/PHP-Antimalware-Scanner)
by Marco Cesarato, licensed **GPL-3.0**. This repository does **not** contain
it, does not vendor it, and does not distribute it. You download it yourself.

That is a deliberate choice, not an oversight.

## Why the separation matters

This scanner invokes AMWScan as a **separate operating-system process** via
`exec()`, at arm's length, exchanging only a command line and a log file. It
does not link against AMWScan, include its source, or import its code.

Two consequences:

1. **Do not commit AMWScan (`scanner`) to a fork of this repository.** `.gitignore`
   excludes it. Shipping both together in one distribution weakens the argument
   that they are separate works and may pull this project's code under GPL-3.0.
2. **If you intend to sell a closed-source product built on this**, get legal
   advice first. GPL-3.0 does not prevent charging money, but if a court or your
   counsel treats your work as a derivative of AMWScan, recipients gain the right
   to the source and to redistribute it.

## If you would rather not think about any of this

Relicense your fork **GPL-3.0** to match AMWScan. That removes the ambiguity
entirely, at the cost of the same obligations flowing to your users.

## Changing the licence of this project

Replace `LICENSE` with the canonical text of your chosen licence from the
issuing body — [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0.txt) if
you want an explicit patent grant, [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.txt)
if you want copyleft — and update the header of this file. Do not paraphrase
licence text.

**None of the above is legal advice.** It is a description of how the pieces fit
together, written by the people who assembled them.
