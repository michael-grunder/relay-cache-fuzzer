# Relay Cache Fuzzer

`relay-cache-fuzzer` stresses Relay's shared cache invalidation behavior when
PHP CLI-server workers exit, are killed, or are replaced while they may own
cached keys or writer slots.

The fuzzer is intentionally not a strict linearizability tester. Relay has
lock-free read paths, so short transient races can happen under concurrent
mutation. The failure condition this project looks for is a stale Redis value
that persists across repeated reads after Redis has been updated and retries
have had time to observe invalidation state.

## Requirements

- PHP with the Relay extension loaded.
- A Redis server reachable by TCP.
- Composer dependencies installed with `composer install`.
- `posix` support in PHP if worker killing is enabled.

When working from a full PHP build tree, prefer the build-tree CLI binary. For
example:

```bash
/home/mike/dev/phpfarm/src/php-8.5.0-debug/sapi/cli/php -m
```

That binary should list `relay`, `redis`, and `posix`.

## Quick Start

Run a short two-worker smoke test:

```bash
bin/relay-cache-fuzzer \
  --php=/home/mike/dev/phpfarm/src/php-8.5.0-debug/sapi/cli/php \
  --workers=2 \
  --duration=10 \
  --keys-per-worker=4 \
  --relay-max-endpoint-dbs=1 \
  --relay-max-db-writers=1
```

Run a parallel harness campaign:

```bash
bin/harness \
  --jobs=16 \
  --work-dir="$PWD" \
  -- \
  bin/relay-cache-fuzzer \
    --mode=simple-sequential \
    --workers=8
```

The harness treats `relay-cache-fuzzer` as an inferior process. It appends a
unique `--run-id`, `--seed`, and `--keyspace-isolated` to each run, records
per-run logs under `artifacts/runs/` while a run is active, removes successful
run artifacts by default, and copies flaw artifacts into
`artifacts/failures/000001`, `000002`, and so on. Inferior exit codes are:
`0` for normal completion, `1` for setup or infrastructure errors, and `2` for
flaws with reproducers. Pass `--keep-run-artifacts` to preserve successful
per-run artifacts for manual inspection.

Integer fuzzer arguments can be templated for reduction:

```bash
bin/harness \
  --jobs=32 \
  --reduce \
  -- \
  bin/relay-cache-fuzzer \
    --mode=normal \
    --commands-per-worker='{{COMMANDS=10000}}'
```

Capture rr traces during a reduced sequential campaign:

```bash
bin/harness \
  --jobs=46 \
  --work-dir="$PWD" \
  --reduce \
  --tui \
  -- \
  bin/relay-cache-fuzzer \
    --mode=simple-sequential \
    --rr \
    --rr-trace-dir="$PWD/artifacts/rr" \
    --keys=10 \
    --client=relay \
    --php=/home/mike/dev/phpfarm/src/php-8.5.0-debug/sapi/cli/php \
    --commands-per-worker='{{COMMANDS=100}}' \
    --workers=4 \
    --keys-per-worker=4 \
    --delay-us=10000 \
    --verify-retries=8 \
    --verify-delay-us=10000 \
    --relay-max-endpoint-dbs=1 \
    --relay-max-db-writers=4
```

The harness passes `--rr` through to the fuzzer. The fuzzer runs the PHP CLI
server under `rr record`, writes each run below the configured trace root, and
copies finalized traces for failing sequential runs into the harness failure
artifact at `artifacts/failures/000001/reproducer/rr/`.

Run a longer capacity-pressure test:

```bash
bin/relay-cache-fuzzer \
  --php=/home/mike/dev/phpfarm/src/php-8.5.0-debug/sapi/cli/php \
  --workers=8 \
  --duration=300 \
  --keys-per-worker=16 \
  --warmup-reads=32 \
  --verify-retries=12 \
  --verify-delay-us=50000 \
  --log-level=debug \
  --relay-max-endpoint-dbs=2 \
  --relay-max-db-writers=2 \
  --kill-rate=0.35 \
  --max-kill=3
```

Run the deterministic shutdown sequence:

```bash
bin/relay-cache-fuzzer \
  --mode=sequential \
  --php=/home/mike/dev/phpfarm/src/php-8.5.0-debug/sapi/cli/php \
  --workers=4 \
  --keys-per-worker=4 \
  --delay-us=50000 \
  --verify-retries=8 \
  --verify-delay-us=50000 \
  --relay-max-endpoint-dbs=1 \
  --relay-max-db-writers=1
```

If `--seed` is omitted, the fuzzer generates one and prints it. Pass the seed
back in to reproduce the same randomized decisions as closely as process
scheduling allows.

## How It Works

The driver starts PHP's built-in CLI server with `PHP_CLI_SERVER_WORKERS=N`,
or with `--fpm` starts an ephemeral static php-fpm pool behind a self-contained
nginx instance. Both transports serve [router.php](router.php), which exposes
deterministic endpoints that only read through Relay:

- `GET /pid`
- `GET /get?key=KEY`
- `GET /warm?key=KEY&n=N`
- `GET /tracked?key=KEY`
- `GET /many?prefix=PFX&n=N`

Redis mutations are performed only by the external driver. This lets server
workers cache values through Relay while the driver updates the authoritative
Redis values directly.

Each observed worker PID receives string keys in this format:

```text
relay-fuzz:{run_id}:{pid}:{slot}
```

The driver warms keys through the configured server-side client, increments
selected keys directly in Redis, kills workers with a configurable signal mix,
rediscovers workers, and then verifies that repeated `/get` requests eventually
return the latest Redis generation.

## Options

Common options:

- `--mode=normal|sequential|simple-sequential`: choose randomized fuzzing, the worker-owned deterministic shutdown sequence, or the shared-key sequential stale-cache mode.
- `--php=/path/to/php`: PHP binary used for the CLI server.
- `--fpm`: use generated php-fpm and nginx configs instead of PHP's CLI server.
- `--php-fpm=/path/to/php-fpm`: php-fpm binary for `--fpm`. Default: `php-fpm`.
- `--nginx=/path/to/nginx`: nginx binary for `--fpm`. Default: `nginx`.
- `--fpm-conf-stub=PATH`: append global php-fpm settings to the generated config.
- `--fpm-pool-conf-stub=PATH`: append pool settings to the generated pool config.
- `--client=relay|redis`: Redis client used by router.php. `relay` tests `Relay\Relay`; `redis` uses PhpRedis as a sanity check for the fuzzing mechanism.
- `--host=127.0.0.1`: server bind host.
- `--port=0`: server port. `0` chooses a free port. Under `bin/harness --jobs=N`, `--fpm --port=BASE` uses `BASE + job_index` for job indexes `0..N-1`.
- `--redis-host=127.0.0.1`
- `--redis-port=6379`
- `--redis-db=0`
- `--workers=N`: CLI-server worker count, or static php-fpm worker count under `--fpm`.
- `--duration=SECONDS`: randomized-mode wall-clock limit. Default: 60. Ignored when `--commands-per-worker` is set.
- `--commands-per-worker=N`: randomized-mode command-count limit for small reproducers. The fuzzer stops after roughly `N * --workers` successful worker-handled HTTP commands in the main fuzz phase, checked between iterations.
- `--seed=N`
- `--relay-max-endpoint-dbs=N`
- `--relay-max-db-writers=N`
- `--capture-relay-log[=LEVEL]`: capture Relay's own log at `debug`, `notice`, `warning`, or `error`. Omitting `LEVEL`, or passing an unsupported level, uses `debug`. Captured logs are written to `relay.log` in the per-run server runtime directory, which is preserved when capture is enabled and copied to `server-runtime/relay.log` in failure bundles.
- `--kill-rate=FLOAT`
- `--max-kill=N`
- `--keys=N`: shared keyspace size for `simple-sequential`.
- `--mutations=N`: Redis mutations after each worker death in `simple-sequential`.
- `--keys-per-worker=N`
- `--warmup-reads=N`
- `--verify-retries=N`
- `--verify-delay-us=N`
- `--delay-us=N`: delay between sequential-mode operations. Defaults to a small nonzero delay.
- `--request-timeout-ms=N`
- `--watchdog-timeout-ms=N`
- `--signal-mix=TERM:60,INT:20,KILL:20`
- `--signals=SIGINT,SIGTERM,SIGQUIT`: signal set for `simple-sequential`.
- `--log-level=info`: one of `debug`, `info`, `notice`, `warning`, `error`, `critical`, `alert`, `emergency`. `--verbose` is equivalent to `--log-level=debug` unless an explicit level is passed.
- `--log-file=PATH`: write human diagnostics to a file instead of stderr.
- `--rr`: run the PHP CLI server under `rr record` in sequential modes.
- `--rr-trace-dir=PATH`: use `PATH` as the rr trace root. The fuzzer creates a unique run directory below it.
- `--verbose`
- `--keep-temp`
- `--fail-fast`

Show the current help text:

```bash
bin/relay-cache-fuzzer --help
```

## Failures And Diagnostics

By default, the fuzzer captures only `stale_key` reproducers. Use
`--capture=stale_key,crash,stuck,other` or `--capture=all` to include other
failure classes.

On randomized-mode failure, the fuzzer writes a reproducer directory named like:

```text
reproducers/random/stale_key/00001/reproducer.json
```

The `reproducer.json` file includes:

- seed and run id
- PHP binary and full server command line
- Redis endpoint
- Relay INI values
- observed and killed worker PIDs
- request, mutation, and stale-observation tails
- server stdout and stderr tails
- startup PHP server process metadata in `server-processes.txt` and
  `server-processes.json`
- the event stream leading to failure

When `--fpm` is used, the bundle also includes `server-runtime/` with generated
nginx/php-fpm configs and logs. When `--capture-relay-log[=LEVEL]` is used,
`server-runtime/relay.log` is included for both CLI-server and FPM runs.

Human diagnostics are written to stderr by default, or to `--log-file` when
specified. TTY logs use concise microtime prefixes and rich styling for humans;
file logs stay plain text. Use `--log-level=debug` to see individual cache
warmups, verification reads, Redis mutations, worker signal attempts, retries,
and server output.

Sequential-mode failures write a reproducer directory named like:

```text
reproducers/sequential/stale_key/00001/
```

The bundle contains `startup.json`, `reproducer.json`, `events.log`,
`server.stdout`, `server.stderr`, `server-processes.txt`,
`server-processes.json`, `server-runtime/` for `--fpm` or
`--capture-relay-log` runs, and, when `--rr` was enabled and rr finalized the
trace, an `rr/` copy. The fuzzer waits for rr `incomplete` markers to disappear
before copying a trace into the bundle.

Replay an event stream with:

```bash
bin/relay-cache-fuzzer \
  --php=/home/mike/dev/phpfarm/src/php-8.5.0-debug/sapi/cli/php \
  --replay=reproducers/random/00001/reproducer.json
```

Replay is best-effort because PHP CLI-server worker scheduling and operating
system signal timing are inherently nondeterministic.

## Development

Run syntax checks:

```bash
php -l bin/relay-cache-fuzzer
php -l router.php
php -l src/Config.php
php -l src/Fuzzer.php
```

Run static analysis:

```bash
vendor/bin/phpstan analyze
```

The router should stay deterministic and read-only with respect to Redis.
Mutations belong in the driver so that server-side Relay cache state can become
stale relative to Redis.
