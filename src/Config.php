<?php

declare(strict_types=1);

namespace MichaelGrunder\RelayCacheFuzzer;

final class Config
{
    /**
     * @param array<int, int> $signalWeights
     * @param list<int> $signals
     */
    private function __construct(
        public readonly string $mode,
        public readonly string $php,
        public readonly string $client,
        public readonly string $host,
        public readonly int $port,
        public readonly string $redisHost,
        public readonly int $redisPort,
        public readonly int $redisDb,
        public readonly int $workers,
        public readonly int $durationSeconds,
        public readonly ?int $commandsPerWorker,
        public readonly int $seed,
        public readonly int $relayMaxEndpointDbs,
        public readonly int $relayMaxDbWriters,
        public readonly float $killRate,
        public readonly int $maxKill,
        public readonly int $keys,
        public readonly int $mutations,
        public readonly int $keysPerWorker,
        public readonly int $warmupReads,
        public readonly int $verifyRetries,
        public readonly int $verifyDelayUs,
        public readonly int $delayUs,
        public readonly int $requestTimeoutMs,
        public readonly int $watchdogTimeoutMs,
        public readonly bool $verbose,
        public readonly string $logLevel,
        public readonly ?string $logFile,
        public readonly bool $keepTemp,
        public readonly bool $failFast,
        public readonly ?string $runId,
        public readonly bool $keyspaceIsolated,
        public readonly array $signalWeights,
        public readonly array $signals,
        public readonly ?string $replayFile,
        public readonly bool $rr,
        public readonly ?string $rrTraceDir,
    ) {
    }

    /**
     * @param list<string> $argv
     */
    public static function fromArgv(array $argv): self
    {
        $raw = self::parseArgv($argv);
        $seed = isset($raw['seed']) ? self::int($raw, 'seed') : random_int(1, PHP_INT_MAX);
        $verbose = self::bool($raw, 'verbose');

        return new self(
            mode: self::mode(self::string($raw, 'mode', 'normal')),
            php: self::string($raw, 'php', PHP_BINARY),
            client: self::client(self::string($raw, 'client', 'relay')),
            host: self::string($raw, 'host', '127.0.0.1'),
            port: self::int($raw, 'port', 0),
            redisHost: self::string($raw, 'redis-host', '127.0.0.1'),
            redisPort: self::int($raw, 'redis-port', 6379),
            redisDb: self::int($raw, 'redis-db', 0),
            workers: max(1, self::int($raw, 'workers', 2)),
            durationSeconds: max(1, self::int($raw, 'duration', 60)),
            commandsPerWorker: isset($raw['commands-per-worker']) ? max(1, self::int($raw, 'commands-per-worker')) : null,
            seed: $seed,
            relayMaxEndpointDbs: max(1, self::int($raw, 'relay-max-endpoint-dbs', 1)),
            relayMaxDbWriters: max(1, self::int($raw, 'relay-max-db-writers', 1)),
            killRate: max(0.0, min(1.0, self::float($raw, 'kill-rate', 0.25))),
            maxKill: max(1, self::int($raw, 'max-kill', 1)),
            keys: max(1, self::int($raw, 'keys', 100)),
            mutations: max(1, self::int($raw, 'mutations', 1)),
            keysPerWorker: max(1, self::int($raw, 'keys-per-worker', 4)),
            warmupReads: max(1, self::int($raw, 'warmup-reads', 16)),
            verifyRetries: max(1, self::int($raw, 'verify-retries', 8)),
            verifyDelayUs: max(0, self::int($raw, 'verify-delay-us', 50000)),
            delayUs: max(0, self::int($raw, 'delay-us', 50000)),
            requestTimeoutMs: max(1, self::int($raw, 'request-timeout-ms', 1000)),
            watchdogTimeoutMs: max(1, self::int($raw, 'watchdog-timeout-ms', 5000)),
            verbose: $verbose,
            logLevel: self::logLevel(self::string($raw, 'log-level', $verbose ? 'debug' : 'info')),
            logFile: isset($raw['log-file']) ? self::string($raw, 'log-file') : null,
            keepTemp: self::bool($raw, 'keep-temp'),
            failFast: self::bool($raw, 'fail-fast'),
            runId: isset($raw['run-id']) ? self::runId(self::string($raw, 'run-id')) : null,
            keyspaceIsolated: self::bool($raw, 'keyspace-isolated'),
            signalWeights: self::parseSignalMix(self::string($raw, 'signal-mix', 'TERM:60,INT:20,KILL:20')),
            signals: self::parseSignals(self::string($raw, 'signals', 'SIGINT,SIGTERM,SIGQUIT')),
            replayFile: isset($raw['replay']) ? self::string($raw, 'replay') : null,
            rr: self::bool($raw, 'rr'),
            rrTraceDir: isset($raw['rr-trace-dir']) ? self::string($raw, 'rr-trace-dir') : null,
        );
    }

    public function withPort(int $port): self
    {
        return new self(
            mode: $this->mode,
            php: $this->php,
            client: $this->client,
            host: $this->host,
            port: $port,
            redisHost: $this->redisHost,
            redisPort: $this->redisPort,
            redisDb: $this->redisDb,
            workers: $this->workers,
            durationSeconds: $this->durationSeconds,
            commandsPerWorker: $this->commandsPerWorker,
            seed: $this->seed,
            relayMaxEndpointDbs: $this->relayMaxEndpointDbs,
            relayMaxDbWriters: $this->relayMaxDbWriters,
            killRate: $this->killRate,
            maxKill: $this->maxKill,
            keys: $this->keys,
            mutations: $this->mutations,
            keysPerWorker: $this->keysPerWorker,
            warmupReads: $this->warmupReads,
            verifyRetries: $this->verifyRetries,
            verifyDelayUs: $this->verifyDelayUs,
            delayUs: $this->delayUs,
            requestTimeoutMs: $this->requestTimeoutMs,
            watchdogTimeoutMs: $this->watchdogTimeoutMs,
            verbose: $this->verbose,
            logLevel: $this->logLevel,
            logFile: $this->logFile,
            keepTemp: $this->keepTemp,
            failFast: $this->failFast,
            runId: $this->runId,
            keyspaceIsolated: $this->keyspaceIsolated,
            signalWeights: $this->signalWeights,
            signals: $this->signals,
            replayFile: $this->replayFile,
            rr: $this->rr,
            rrTraceDir: $this->rrTraceDir,
        );
    }

    /**
     * @param list<string> $argv
     * @return array<string, string|bool>
     */
    private static function parseArgv(array $argv): array
    {
        $out = [];
        $count = count($argv);

        for ($i = 1; $i < $count; $i++) {
            $arg = $argv[$i];

            if ($arg === '--help' || $arg === '-h') {
                self::printHelp();
                exit(0);
            }

            if (!str_starts_with($arg, '--')) {
                throw new FuzzerException("Unexpected argument: {$arg}");
            }

            $arg = substr($arg, 2);
            $eq = strpos($arg, '=');

            if ($eq !== false) {
                $out[substr($arg, 0, $eq)] = substr($arg, $eq + 1);
                continue;
            }

            if ($i + 1 < $count && !str_starts_with($argv[$i + 1], '--')) {
                $out[$arg] = $argv[++$i];
            } else {
                $out[$arg] = true;
            }
        }

        return $out;
    }

    private static function printHelp(): void
    {
        echo <<<'HELP'
Relay cache fuzzer

Usage:
  bin/relay-cache-fuzzer [options]
  bin/relay-cache-fuzzer --mode=normal --php=/path/to/php --duration=30
  bin/relay-cache-fuzzer --mode=normal --commands-per-worker=5 --seed=1234
  bin/relay-cache-fuzzer --mode=sequential --workers=4 --delay-us=50000
  bin/relay-cache-fuzzer --mode=simple-sequential --workers=4 --keys=100 --mutations=5
  bin/relay-cache-fuzzer --replay=reproducers/random/00001/reproducer.json

Purpose:
  Exercises Relay cache invalidation when PHP CLI-server workers cache keys,
  die, are replaced, and later serve reads for keys that were changed directly
  in Redis by the driver.

Run modes:
  --mode=normal
      Randomized fuzzing. The driver discovers workers, warms keys through the
      configured server-side client, mutates Redis directly, may kill one or
      more workers, and verifies reads through the PHP server. This is the
      default.

  --mode=sequential
      Deterministic worker-shutdown sequence. Workers are discovered, warmed,
      killed one at a time, and surviving workers are queried for stale values.
      This mode is slower and more structured, which is useful after the random
      mode has identified a bug class.

  --mode=simple-sequential
      Simplified shared-key sequential mode. The driver flushes Redis, creates
      one deterministic shared keyspace, warms it through the PHP server, then
      repeatedly kills one initially discovered worker, mutates Redis directly,
      and verifies the entire keyspace through Relay. This mode does not assign
      keys to workers and is intended for rr-friendly stale-cache debugging.

Execution limit:
  --duration=SECONDS
      Run randomized fuzzing for this many seconds. Must be an integer >= 1.
      Default: 60. Ignored when --commands-per-worker is specified.

  --commands-per-worker=N
      Randomized-mode command-count limit for small reproducers. Instead of
      running by wall-clock duration, stop after approximately N successful
      HTTP commands per configured worker in the main fuzz phase. The total
      target is N * --workers. Must be an integer >= 1.

      The limit is checked between randomized iterations, so the final command
      count can exceed the exact target by the size of one iteration. Use small
      values such as 1, 2, 5, or 10 when reducing failures.

Server and client:
  --php=PATH
      PHP binary used for the CLI server. Default: the PHP binary running this
      script. Prefer a PHP build-tree binary such as ../php-*/sapi/cli/php when
      testing Relay from source.

  --client=relay|redis
      Server-side Redis client used by router.php. relay tests Relay\Relay.
      redis uses PhpRedis as a control to validate the fuzzer mechanism.
      Default: relay.

  --host=HOST
      PHP CLI-server bind host. Default: 127.0.0.1.

  --port=PORT
      PHP CLI-server port. Use 0 to pick a free port. Default: 0.

  --workers=N
      PHP_CLI_SERVER_WORKERS value. Must be an integer >= 1. Default: 2.

Redis:
  --redis-host=HOST
      Redis host used by both the driver and router. Default: 127.0.0.1.

  --redis-port=PORT
      Redis TCP port. Default: 6379.

  --redis-db=N
      Redis database number. Default: 0.

Relay INI:
  --relay-max-endpoint-dbs=N
      relay.max_endpoint_dbs passed to the PHP CLI server. Must be >= 1.
      Default: 1.

  --relay-max-db-writers=N
      relay.max_db_writers passed to the PHP CLI server. Must be >= 1.
      Default: 1.

Randomized fuzzing:
  --seed=N
      Random seed. If omitted, a seed is generated and logged. Reuse a printed
      seed to replay the same pseudo-random choices.

  --kill-rate=FLOAT
      Probability that a randomized iteration kills workers. Valid values are
      clamped to 0.0 through 1.0. Default: 0.25.

  --max-kill=N
      Maximum workers to kill in one randomized iteration. Must be >= 1.
      Default: 1.

  --signal-mix=SPEC
      Weighted signal distribution for worker kills. SPEC is a comma-separated
      list of signal names and optional weights. Supported signals are TERM,
      INT, and KILL, with or without a SIG prefix. Default:
      TERM:60,INT:20,KILL:20.

      Examples: --signal-mix=TERM, --signal-mix=SIGTERM:90,SIGKILL:10

Keys and verification:
  --keys=N
      Shared keyspace size for simple-sequential mode. Must be >= 1.
      Default: 100.

  --mutations=N
      Number of random Redis mutations after each worker death in
      simple-sequential mode. Must be >= 1. Default: 1.

  --signals=SIGINT,SIGTERM,SIGQUIT
      Comma-separated signal set for simple-sequential worker kills. Supported
      signals are INT, TERM, QUIT, KILL, and ABRT, with or without a SIG prefix.
      Default: SIGINT,SIGTERM,SIGQUIT.

  --keys-per-worker=N
      Redis keys assigned to each observed worker PID. Must be >= 1.
      Default: 4.

  --warmup-reads=N
      Number of repeated reads performed by each /warm request. Must be >= 1.
      Default: 16.

  --verify-retries=N
      Number of /get attempts before a mismatched value is considered a
      persistent stale failure. Must be >= 1. Default: 8.

  --verify-delay-us=N
      Microseconds to wait between verification retries. Must be >= 0.
      Default: 50000.

  --delay-us=N
      Sequential-mode delay between operations. Must be >= 0. Default: 50000.

Timeouts and watchdog:
  --request-timeout-ms=N
      Per-request HTTP and Redis timeout in milliseconds. Must be >= 1.
      Default: 1000.

  --watchdog-timeout-ms=N
      Abort if no successful request completes within this many milliseconds.
      Must be >= 1. Default: 5000.

Logging and diagnostics:
  --log-level=LEVEL
      Human log level. Valid values: debug, info, notice, warning, error,
      critical, alert, emergency. warn is accepted as warning. Default: info,
      or debug when --verbose is set.

  --log-file=PATH
      Write human diagnostics to PATH instead of stderr.

  --verbose
      Shortcut for --log-level=debug unless --log-level is also specified.

  --keep-temp
      Preserve temporary diagnostic directories that would otherwise be removed.

  --fail-fast
      Parsed for compatibility with reproducer command lines.

  --run-id=ID
      Override the generated run identifier. Harness launches pass a globally
      unique run id so parallel inferiors use disjoint Redis key names.

  --keyspace-isolated
      Avoid global Redis keyspace mutations such as FLUSHDB in modes that can
      otherwise use them. This is intended for harness-launched parallel runs.

Replay and rr:
  --replay=PATH
      Replay a randomized reproducer JSON file. The replay is best-effort
      because PHP CLI-server worker scheduling is not deterministic.

  --rr
      Run the PHP CLI server under rr record in sequential modes.

  --rr-trace-dir=PATH
      Use PATH as the rr trace root. The fuzzer creates a unique run directory
      below it.

Help:
  -h, --help
      Show this help text.

HELP;
    }

    /**
     * @param array<string, string|bool> $raw
     */
    private static function string(array $raw, string $key, ?string $default = null): string
    {
        if (!isset($raw[$key])) {
            if ($default === null) {
                throw new FuzzerException("Missing required option --{$key}");
            }

            return $default;
        }

        if ($raw[$key] === true) {
            throw new FuzzerException("Option --{$key} requires a value");
        }

        return $raw[$key];
    }

    /**
     * @param array<string, string|bool> $raw
     */
    private static function int(array $raw, string $key, int $default = 0): int
    {
        $value = self::string($raw, $key, (string) $default);

        if (!preg_match('/^-?\d+$/', $value)) {
            throw new FuzzerException("Option --{$key} must be an integer");
        }

        return (int) $value;
    }

    /**
     * @param array<string, string|bool> $raw
     */
    private static function float(array $raw, string $key, float $default): float
    {
        $value = self::string($raw, $key, (string) $default);

        if (!is_numeric($value)) {
            throw new FuzzerException("Option --{$key} must be numeric");
        }

        return (float) $value;
    }

    /**
     * @param array<string, string|bool> $raw
     */
    private static function bool(array $raw, string $key): bool
    {
        return isset($raw[$key]) && $raw[$key] !== '0' && $raw[$key] !== 'false';
    }

    private static function logLevel(string $level): string
    {
        $level = strtolower($level);

        if ($level === 'warn') {
            return 'warning';
        }

        $levels = ['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'];

        if (!in_array($level, $levels, true)) {
            throw new FuzzerException('--log-level must be one of debug, info, notice, warning, error, critical, alert, emergency');
        }

        return $level;
    }

    private static function mode(string $mode): string
    {
        $mode = strtolower($mode);

        if (!in_array($mode, ['normal', 'sequential', 'simple-sequential'], true)) {
            throw new FuzzerException('--mode must be one of normal, sequential, simple-sequential');
        }

        return $mode;
    }

    private static function client(string $client): string
    {
        $client = strtolower($client);

        if (!in_array($client, ['relay', 'redis'], true)) {
            throw new FuzzerException('--client must be one of relay, redis');
        }

        return $client;
    }

    private static function runId(string $runId): string
    {
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/', $runId)) {
            throw new FuzzerException('--run-id must contain only letters, digits, dots, underscores, colons, or hyphens');
        }

        return $runId;
    }

    /**
     * @return array<int, int>
     */
    private static function parseSignalMix(string $mix): array
    {
        $signals = ['INT' => 2, 'TERM' => 15, 'KILL' => 9];
        $weights = [];

        foreach (explode(',', $mix) as $part) {
            $part = trim($part);

            if ($part === '') {
                continue;
            }

            [$name, $weight] = array_pad(explode(':', $part, 2), 2, '1');
            $name = strtoupper(trim($name));

            if (str_starts_with($name, 'SIG')) {
                $name = substr($name, 3);
            }

            if (!isset($signals[$name])) {
                throw new FuzzerException("Unsupported signal in --signal-mix: {$name}");
            }

            $weights[$signals[$name]] = max(0, (int) $weight);
        }

        if (array_sum($weights) <= 0) {
            throw new FuzzerException('--signal-mix must contain at least one positive weight');
        }

        return $weights;
    }

    /**
     * @return list<int>
     */
    private static function parseSignals(string $list): array
    {
        $supported = ['INT' => 2, 'TERM' => 15, 'QUIT' => 3, 'KILL' => 9, 'ABRT' => 6];
        $signals = [];

        foreach (explode(',', $list) as $part) {
            $name = strtoupper(trim($part));

            if ($name === '') {
                continue;
            }

            if (str_starts_with($name, 'SIG')) {
                $name = substr($name, 3);
            }

            if (!isset($supported[$name])) {
                throw new FuzzerException("Unsupported signal in --signals: {$name}");
            }

            $signals[] = $supported[$name];
        }

        if ($signals === []) {
            throw new FuzzerException('--signals must contain at least one signal');
        }

        return array_values(array_unique($signals));
    }
}
