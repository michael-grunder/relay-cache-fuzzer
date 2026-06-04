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
  --relay-max-endpoint-dbs=2 \
  --relay-max-db-writers=2 \
  --kill-rate=0.35 \
  --max-kill=3
```

If `--seed` is omitted, the fuzzer generates one and prints it. Pass the seed
back in to reproduce the same randomized decisions as closely as process
scheduling allows.

## How It Works

The driver starts PHP's built-in CLI server with `PHP_CLI_SERVER_WORKERS=N`
and serves [router.php](router.php). The router exposes deterministic endpoints
that only read through Relay:

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

The driver warms keys through Relay, increments selected keys directly in
Redis, kills workers with a configurable signal mix, rediscovers workers, and
then verifies that repeated `/get` requests eventually return the latest Redis
generation.

## Options

Common options:

- `--php=/path/to/php`: PHP binary used for the CLI server.
- `--host=127.0.0.1`: CLI server bind host.
- `--port=0`: CLI server port. `0` chooses a free port.
- `--redis-host=127.0.0.1`
- `--redis-port=6379`
- `--redis-db=0`
- `--workers=N`: `PHP_CLI_SERVER_WORKERS`.
- `--duration=SECONDS`
- `--seed=N`
- `--relay-max-endpoint-dbs=N`
- `--relay-max-db-writers=N`
- `--kill-rate=FLOAT`
- `--max-kill=N`
- `--keys-per-worker=N`
- `--warmup-reads=N`
- `--verify-retries=N`
- `--verify-delay-us=N`
- `--request-timeout-ms=N`
- `--watchdog-timeout-ms=N`
- `--signal-mix=TERM:60,INT:20,KILL:20`
- `--verbose`
- `--keep-temp`
- `--fail-fast`

Show the current help text:

```bash
bin/relay-cache-fuzzer --help
```

## Failures And Diagnostics

On failure, the fuzzer writes a JSON reproducer file named like:

```text
relay-cache-fuzzer-failure-{run_id}-{timestamp}.json
```

The file includes:

- seed and run id
- PHP binary and full server command line
- Redis endpoint
- Relay INI values
- observed and killed worker PIDs
- request, mutation, and stale-observation tails
- server stdout and stderr tails
- the event stream leading to failure

Replay an event stream with:

```bash
bin/relay-cache-fuzzer \
  --php=/home/mike/dev/phpfarm/src/php-8.5.0-debug/sapi/cli/php \
  --replay=relay-cache-fuzzer-failure-...json
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
