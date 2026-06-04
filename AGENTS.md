## Relay Cache Fuzzer Notes

This directory is a standalone Composer project for exercising Relay from a
PHP source tree or an installed PHP binary.

- Prefer running the fuzzer with the PHP build tree binary when available:
  `../php-*/sapi/cli/php` or the absolute `sapi/cli/php` path from the build
  root.
- The fuzzer starts PHP's built-in CLI server and passes Relay INI settings to
  that same PHP binary.
- Keep the router deterministic and read-only with respect to Redis. Redis
  mutations belong in the external driver.
- Run static analysis with `vendor/bin/phpstan analyze`.
- For quick syntax checks, use `php -l` on changed PHP files.
