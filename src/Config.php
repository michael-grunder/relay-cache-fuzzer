<?php

declare(strict_types=1);

namespace MichaelGrunder\RelayCacheFuzzer;

final class Config
{
    /**
     * @param array<int, int> $signalWeights
     */
    private function __construct(
        public readonly string $mode,
        public readonly string $php,
        public readonly string $host,
        public readonly int $port,
        public readonly string $redisHost,
        public readonly int $redisPort,
        public readonly int $redisDb,
        public readonly int $workers,
        public readonly int $durationSeconds,
        public readonly int $seed,
        public readonly int $relayMaxEndpointDbs,
        public readonly int $relayMaxDbWriters,
        public readonly float $killRate,
        public readonly int $maxKill,
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
        public readonly array $signalWeights,
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
            host: self::string($raw, 'host', '127.0.0.1'),
            port: self::int($raw, 'port', 0),
            redisHost: self::string($raw, 'redis-host', '127.0.0.1'),
            redisPort: self::int($raw, 'redis-port', 6379),
            redisDb: self::int($raw, 'redis-db', 0),
            workers: max(1, self::int($raw, 'workers', 2)),
            durationSeconds: max(1, self::int($raw, 'duration', 60)),
            seed: $seed,
            relayMaxEndpointDbs: max(1, self::int($raw, 'relay-max-endpoint-dbs', 1)),
            relayMaxDbWriters: max(1, self::int($raw, 'relay-max-db-writers', 1)),
            killRate: max(0.0, min(1.0, self::float($raw, 'kill-rate', 0.25))),
            maxKill: max(1, self::int($raw, 'max-kill', 1)),
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
            signalWeights: self::parseSignalMix(self::string($raw, 'signal-mix', 'TERM:60,INT:20,KILL:20')),
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
            host: $this->host,
            port: $port,
            redisHost: $this->redisHost,
            redisPort: $this->redisPort,
            redisDb: $this->redisDb,
            workers: $this->workers,
            durationSeconds: $this->durationSeconds,
            seed: $this->seed,
            relayMaxEndpointDbs: $this->relayMaxEndpointDbs,
            relayMaxDbWriters: $this->relayMaxDbWriters,
            killRate: $this->killRate,
            maxKill: $this->maxKill,
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
            signalWeights: $this->signalWeights,
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
        echo "Usage: bin/relay-cache-fuzzer --php=/path/to/php [options]\n";
        echo "\n";
        echo "Options include --mode=normal|sequential, --host, --port, --redis-host, --redis-port, --redis-db,\n";
        echo "--workers, --duration, --seed, --relay-max-endpoint-dbs,\n";
        echo "--relay-max-db-writers, --kill-rate, --max-kill, --keys-per-worker,\n";
        echo "--warmup-reads, --verify-retries, --verify-delay-us, --delay-us,\n";
        echo "--request-timeout-ms, --signal-mix, --log-level, --log-file,\n";
        echo "--replay, --rr, --rr-trace-dir, --verbose,\n";
        echo "--keep-temp, and --fail-fast.\n";
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

        if (!in_array($mode, ['normal', 'sequential'], true)) {
            throw new FuzzerException('--mode must be one of normal, sequential');
        }

        return $mode;
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
}
