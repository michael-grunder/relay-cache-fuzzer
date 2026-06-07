<?php

declare(strict_types=1);

namespace MichaelGrunder\RelayCacheFuzzer;

use Monolog\Formatter\FormatterInterface;
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\LogRecord;
use Monolog\Logger as MonologLogger;
use Psr\Log\LoggerInterface;
use Random\Engine\Mt19937;
use Random\Randomizer;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use Symfony\Component\Process\Process;
use Throwable;

final class FuzzerException extends RuntimeException
{
}

final class RequestException extends RuntimeException
{
    public function __construct(string $message, public readonly bool $timedOut = false)
    {
        parent::__construct($message);
    }
}

final class ReproducerPaths
{
    public static function createBundleDirectory(string $mode, string $type): string
    {
        $root = getcwd() . DIRECTORY_SEPARATOR . 'reproducers' . DIRECTORY_SEPARATOR . $mode . DIRECTORY_SEPARATOR . $type;

        if (!is_dir($root) && !mkdir($root, 0777, true) && !is_dir($root)) {
            throw new FuzzerException("Could not create reproducer root {$root}");
        }

        for ($i = 1; $i <= 99999; $i++) {
            $path = $root . DIRECTORY_SEPARATOR . sprintf('%05d', $i);

            if (@mkdir($path)) {
                return $path;
            }

            if (is_dir($path)) {
                continue;
            }

            throw new FuzzerException("Could not create reproducer bundle {$path}");
        }

        throw new FuzzerException("Could not allocate reproducer bundle under {$root}");
    }
}

final class ReproducerTypes
{
    public const STALE_KEY = 'stale_key';
    public const CRASH = 'crash';
    public const STUCK = 'stuck';
    public const OTHER = 'other';

    /**
     * @param array<string, mixed> $context
     * @param array<string, int> $stats
     */
    public static function classify(string $reason, array $context, array $stats, ?ServerProcess $server, bool $serverStopTimedOut): string
    {
        if (($stats['stale_observations'] ?? 0) > 0) {
            return self::STALE_KEY;
        }

        if ($serverStopTimedOut) {
            return self::STUCK;
        }

        if ($server?->crashingSignalName() !== null) {
            return self::CRASH;
        }

        return self::OTHER;
    }

    /**
     * @param array<string, true> $captureTypes
     */
    public static function shouldCapture(array $captureTypes, string $type): bool
    {
        return isset($captureTypes[$type]);
    }
}

final class StaleSequenceLog
{
    /**
     * @param list<array<string, mixed>> $events
     * @param array<string, mixed> $context
     * @return list<string>
     */
    public static function lines(array $events, array $context): array
    {
        $key = self::failureKey($context);
        $selected = self::selectEvents($events, $key);

        if ($selected === []) {
            return [];
        }

        $start = self::eventTime($selected[0]) ?? 0.0;
        $lastMutationAt = null;
        $lines = [];

        foreach ($selected as $event) {
            $time = self::eventTime($event);

            if (self::isMutation($event)) {
                $lastMutationAt = $time;
            }

            $line = self::formatEvent($event, $start, $lastMutationAt);

            if ($line !== null) {
                $lines[] = $line;
            }
        }

        return $lines;
    }

    /**
     * @param array<string, mixed> $context
     */
    private static function failureKey(array $context): ?string
    {
        if (isset($context['key']) && is_string($context['key'])) {
            return $context['key'];
        }

        if (isset($context['last_mismatch']) && is_array($context['last_mismatch'])) {
            $key = $context['last_mismatch']['key'] ?? null;

            if (is_string($key)) {
                return $key;
            }
        }

        return null;
    }

    /**
     * @param list<array<string, mixed>> $events
     * @return list<array<string, mixed>>
     */
    private static function selectEvents(array $events, ?string $key): array
    {
        if ($events === []) {
            return [];
        }

        if ($key === null) {
            return array_slice($events, -80);
        }

        $failureIndex = null;
        $mutationIndex = null;
        $readBeforeMutationIndex = null;

        foreach ($events as $index => $event) {
            if (self::isRead($event) && ($event['key'] ?? null) === $key && ($event['value'] ?? null) !== ($event['expected'] ?? null)) {
                $failureIndex = $index;
            }
        }

        $end = $failureIndex ?? array_key_last($events);

        for ($index = $end; $index >= 0; $index--) {
            if (self::isMutationForKey($events[$index], $key)) {
                $mutationIndex = $index;
                break;
            }
        }

        if ($mutationIndex !== null) {
            for ($index = $mutationIndex - 1; $index >= 0; $index--) {
                if (self::isRead($events[$index]) && ($events[$index]['key'] ?? null) === $key) {
                    $readBeforeMutationIndex = $index;
                    break;
                }
            }
        }

        $start = $readBeforeMutationIndex ?? $mutationIndex ?? max(0, $end - 40);
        $selected = [];

        for ($index = $start; $index <= $end; $index++) {
            $event = $events[$index];

            if (
                self::isRead($event) && ($event['key'] ?? null) === $key
                || self::isMutationForKey($event, $key)
                || self::isWorkerLifecycle($event)
            ) {
                $selected[] = $event;
            }
        }

        return array_slice($selected, -80);
    }

    /**
     * @param array<string, mixed> $event
     */
    private static function formatEvent(array $event, float $start, ?float $lastMutationAt): ?string
    {
        $prefix = sprintf('[+%s] ', self::formatDuration(self::durationMs(self::eventTime($event), $start)));
        $type = (string) ($event['type'] ?? '');

        if (self::isRead($event)) {
            $status = ($event['value'] ?? null) === ($event['expected'] ?? null) ? 'OK' : 'ERROR';
            $age = $lastMutationAt === null ? '' : ' stale_age=' . self::formatDuration(self::durationMs(self::eventTime($event), $lastMutationAt));

            return $prefix . sprintf(
                '[READ] pid=%s key=%s expected=%s read=%s %s%s tracked=%s attempt=%s',
                self::value($event['pid'] ?? null),
                self::value($event['key'] ?? null),
                self::value($event['expected'] ?? null),
                self::value($event['value'] ?? null),
                $status,
                $status === 'ERROR' ? $age : '',
                self::value($event['tracked'] ?? null),
                self::value($event['attempt'] ?? null),
            );
        }

        if (self::isMutation($event)) {
            $op = self::mutationOp($event);
            $before = $event['previous_expected'] ?? $event['old_expected'] ?? $event['expected_before'] ?? null;
            $after = $event['expected_after'] ?? $event['expected'] ?? $event['value'] ?? null;
            $delta = $before !== null || $after !== null ? ' ' . self::value($before) . '=>' . self::value($after) : '';

            return $prefix . sprintf(
                '[MUTATE] op=%s key=%s%s amount=%s source=driver',
                $op,
                self::value($event['key'] ?? null),
                $delta,
                self::value($event['amount'] ?? null),
            );
        }

        if ($type === 'kill') {
            return $prefix . sprintf(
                '[KILL] pid=%s signal=%s ok=%s',
                self::value($event['pid'] ?? null),
                self::value($event['signal'] ?? null),
                self::value($event['ok'] ?? null),
            );
        }

        if ($type === 'death_observed') {
            return $prefix . sprintf('[DEAD] pid=%s', self::value($event['pid'] ?? null));
        }

        return null;
    }

    /**
     * @param array<string, mixed> $event
     */
    private static function isRead(array $event): bool
    {
        return ($event['type'] ?? null) === 'get';
    }

    /**
     * @param array<string, mixed> $event
     */
    private static function isMutationForKey(array $event, string $key): bool
    {
        if (!self::isMutation($event)) {
            return false;
        }

        $eventKey = $event['key'] ?? null;

        return $eventKey === $key || $eventKey === null;
    }

    /**
     * @param array<string, mixed> $event
     */
    private static function isMutation(array $event): bool
    {
        $type = $event['type'] ?? null;

        return $type === 'incr'
            || $type === 'mutation'
            || ($type === 'set' && ($event['phase'] ?? null) === 'rebuild');
    }

    /**
     * @param array<string, mixed> $event
     */
    private static function isWorkerLifecycle(array $event): bool
    {
        return in_array($event['type'] ?? null, ['kill', 'death_observed'], true);
    }

    /**
     * @param array<string, mixed> $event
     */
    private static function mutationOp(array $event): string
    {
        $op = $event['op'] ?? null;

        if (is_string($op)) {
            return $op;
        }

        return match ($event['type'] ?? null) {
            'incr' => 'INCR',
            'set' => 'SET',
            default => 'MUTATE',
        };
    }

    /**
     * @param array<string, mixed> $event
     */
    private static function eventTime(array $event): ?float
    {
        $time = $event['time'] ?? null;

        return is_numeric($time) ? (float) $time : null;
    }

    private static function durationMs(?float $time, float $start): float
    {
        return max(0.0, (($time ?? $start) - $start) * 1000.0);
    }

    private static function formatDuration(float $ms): string
    {
        return sprintf('%.3fms', $ms);
    }

    private static function value(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        return (string) $value;
    }
}

final class HumanLogFormatter implements FormatterInterface
{
    public function __construct(private readonly bool $decorated)
    {
    }

    public function format(LogRecord $record): string
    {
        $time = sprintf('%.4f', (float) $record->datetime->format('U.u'));
        $level = strtolower($record->level->getName());
        $prefix = "[{$time}]";
        $message = $record->message;
        $context = $this->formatContext($record->context);

        if ($this->decorated) {
            $prefix = $this->color($record->level, $prefix);
            $level = $this->color($record->level, $this->symbol($record->level) . ' ' . $level);
        }

        return "{$prefix} {$level} {$message}{$context}\n";
    }

    /**
     * @param array<LogRecord> $records
     */
    public function formatBatch(array $records): string
    {
        return implode('', array_map($this->format(...), $records));
    }

    /**
     * @param array<string, mixed> $context
     */
    private function formatContext(array $context): string
    {
        if ($context === []) {
            return '';
        }

        $parts = [];

        foreach ($context as $key => $value) {
            $parts[] = $key . '=' . $this->formatValue($value);
        }

        return ' ' . implode(' ', $parts);
    }

    private function formatValue(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_scalar($value)) {
            $value = (string) $value;

            return preg_match('/\s/', $value) ? json_encode($value, JSON_THROW_ON_ERROR) : $value;
        }

        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private function symbol(Level $level): string
    {
        return match (true) {
            $level->value >= Level::Error->value => '✖',
            $level === Level::Warning => '▲',
            $level === Level::Debug => '·',
            default => '•',
        };
    }

    private function color(Level $level, string $value): string
    {
        $code = match (true) {
            $level->value >= Level::Error->value => '31',
            $level === Level::Warning => '33',
            $level === Level::Notice => '36',
            $level === Level::Debug => '2',
            default => '32',
        };

        return "\033[{$code}m{$value}\033[0m";
    }
}

final class LogFactory
{
    public static function create(Config $config): LoggerInterface
    {
        $handler = new StreamHandler($config->logFile ?? 'php://stderr', Level::fromName(strtoupper($config->logLevel)));
        $handler->setFormatter(new HumanLogFormatter($config->logFile === null && self::stderrIsTty()));

        return new MonologLogger('relay-cache-fuzzer', [$handler]);
    }

    private static function stderrIsTty(): bool
    {
        return defined('STDERR') && function_exists('stream_isatty') && stream_isatty(STDERR);
    }
}

final class StartupBlock
{
    /**
     * @param list<array{section: string, setting: string, value: mixed}> $modeRows
     */
    public static function write(Config $config, string $runId, array $modeRows = []): void
    {
        $rows = array_merge(self::baseRows($config, $runId), $modeRows);
        $labelWidth = max(array_map(static fn (array $row): int => strlen(self::formatLabel($row)), $rows));
        $lines = [''];

        foreach ($rows as $row) {
            $lines[] = sprintf(
                '%-' . $labelWidth . 's : %s',
                self::formatLabel($row),
                self::formatValue($row['value'], $row['setting']),
            );
        }

        $lines[] = '';

        @file_put_contents($config->logFile ?? 'php://stderr', implode("\n", $lines) . "\n", FILE_APPEND);
    }

    /**
     * @return list<array{section: string, setting: string, value: mixed}>
     */
    private static function baseRows(Config $config, string $runId): array
    {
        return [
            ['section' => 'run', 'setting' => 'mode', 'value' => $config->mode],
            ['section' => 'run', 'setting' => 'seed', 'value' => $config->seed],
            ['section' => 'run', 'setting' => 'run_id', 'value' => $runId],
            ['section' => 'run', 'setting' => 'server', 'value' => "http://{$config->host}:{$config->port}"],
            ['section' => 'run', 'setting' => 'argv', 'value' => array_values(array_map('strval', $_SERVER['argv'] ?? []))],
            ['section' => 'php_server', 'setting' => 'transport', 'value' => $config->fpm ? 'fpm' : 'cli'],
            ['section' => 'php_server', 'setting' => 'php', 'value' => $config->php],
            ['section' => 'php_server', 'setting' => 'php_fpm', 'value' => $config->phpFpm],
            ['section' => 'php_server', 'setting' => 'nginx', 'value' => $config->nginx],
            ['section' => 'php_server', 'setting' => 'host', 'value' => $config->host],
            ['section' => 'php_server', 'setting' => 'port', 'value' => $config->port],
            ['section' => 'php_server', 'setting' => 'workers', 'value' => $config->workers],
            ['section' => 'php_server', 'setting' => 'client', 'value' => $config->client],
            ['section' => 'php_server', 'setting' => 'fpm_conf_stub', 'value' => $config->fpmConfStub],
            ['section' => 'php_server', 'setting' => 'fpm_pool_conf_stub', 'value' => $config->fpmPoolConfStub],
            ['section' => 'php_server', 'setting' => 'harness_job_index', 'value' => $config->harnessJobIndex],
            ['section' => 'php_server', 'setting' => 'request_timeout_ms', 'value' => $config->requestTimeoutMs],
            ['section' => 'php_server', 'setting' => 'watchdog_timeout_ms', 'value' => $config->watchdogTimeoutMs],
            ['section' => 'redis', 'setting' => 'host', 'value' => $config->redisHost],
            ['section' => 'redis', 'setting' => 'port', 'value' => $config->redisPort],
            ['section' => 'redis', 'setting' => 'db', 'value' => $config->redisDb],
            ['section' => 'redis', 'setting' => 'server', 'value' => $config->redisServer],
            ['section' => 'redis', 'setting' => 'owned', 'value' => $config->redisServer !== null],
            ['section' => 'relay_ini', 'setting' => 'relay.cache', 'value' => 1],
            ['section' => 'relay_ini', 'setting' => 'relay.max_endpoint_dbs', 'value' => $config->relayMaxEndpointDbs],
            ['section' => 'relay_ini', 'setting' => 'relay.max_db_writers', 'value' => $config->relayMaxDbWriters],
            ['section' => 'relay_ini', 'setting' => 'relay.loglevel', 'value' => $config->captureRelayLogLevel],
            ['section' => 'relay_ini', 'setting' => 'relay.logfile', 'value' => $config->captureRelayLogLevel === null ? null : 'server-runtime/relay.log'],
            ['section' => 'keys', 'setting' => 'keys', 'value' => $config->keys],
            ['section' => 'keys', 'setting' => 'keys_per_worker', 'value' => $config->keysPerWorker],
            ['section' => 'keys', 'setting' => 'warmup_reads', 'value' => $config->warmupReads],
            ['section' => 'keys', 'setting' => 'mutations', 'value' => $config->mutations],
            ['section' => 'verification', 'setting' => 'verify_retries', 'value' => $config->verifyRetries],
            ['section' => 'verification', 'setting' => 'verify_delay_us', 'value' => $config->verifyDelayUs],
            ['section' => 'verification', 'setting' => 'delay_us', 'value' => $config->delayUs],
            ['section' => 'random_kill', 'setting' => 'kill_rate', 'value' => $config->killRate],
            ['section' => 'random_kill', 'setting' => 'max_kill', 'value' => $config->maxKill],
            ['section' => 'random_kill', 'setting' => 'signal_weights', 'value' => self::formatSignalWeights($config->signalWeights)],
            ['section' => 'signals', 'setting' => 'simple_sequential_signals', 'value' => array_map(self::signalName(...), $config->signals)],
            ['section' => 'limits', 'setting' => 'duration_seconds', 'value' => $config->durationSeconds],
            ['section' => 'limits', 'setting' => 'commands_per_worker', 'value' => $config->commandsPerWorker],
            ['section' => 'logging', 'setting' => 'log_level', 'value' => $config->logLevel],
            ['section' => 'logging', 'setting' => 'log_file', 'value' => $config->logFile],
            ['section' => 'logging', 'setting' => 'verbose', 'value' => $config->verbose],
            ['section' => 'diagnostics', 'setting' => 'keep_temp', 'value' => $config->keepTemp],
            ['section' => 'diagnostics', 'setting' => 'fail_fast', 'value' => $config->failFast],
            ['section' => 'replay_rr', 'setting' => 'replay_file', 'value' => $config->replayFile],
            ['section' => 'replay_rr', 'setting' => 'rr', 'value' => $config->rr],
            ['section' => 'replay_rr', 'setting' => 'rr_trace_dir', 'value' => $config->rrTraceDir],
        ];
    }

    /**
     * @param array<int, int> $signalWeights
     * @return array<string, int>
     */
    private static function formatSignalWeights(array $signalWeights): array
    {
        $out = [];

        foreach ($signalWeights as $signal => $weight) {
            $out[self::signalName((int) $signal)] = $weight;
        }

        return $out;
    }

    /**
     * @param array{section: string, setting: string, value: mixed} $row
     */
    private static function formatLabel(array $row): string
    {
        $setting = $row['setting'];
        $label = match ($setting) {
            'argv' => 'Argv',
            'commands_per_worker' => 'Commands',
            'db' => 'DB',
            'delay_us' => 'Delay',
            'duration_seconds' => 'Duration',
            'fail_fast' => 'Fail Fast',
            'keep_temp' => 'Keep Temp',
            'log_file' => 'Log File',
            'log_level' => 'Log Level',
            'max_kill' => 'Max Kill',
            'php' => 'PHP',
            'relay.max_db_writers' => 'Relay Max DB Writers',
            'relay.max_endpoint_dbs' => 'Relay Max Endpoint DBs',
            'replay_file' => 'Replay File',
            'request_timeout_ms' => 'Request Timeout',
            'rr' => 'RR',
            'rr_trace_dir' => 'RR Trace Dir',
            'rr_trace_dir_actual' => 'RR Trace Dir Actual',
            'run_id' => 'Run ID',
            'signal_weights' => 'Signal Weights',
            'simple_sequential_signals' => 'Simple Sequential Signals',
            'verify_delay_us' => 'Verify Delay',
            'watchdog_timeout_ms' => 'Watchdog Timeout',
            default => ucwords(str_replace(['_', '.'], ' ', $setting)),
        };

        if (in_array($setting, ['client', 'host', 'port'], true)) {
            return self::formatSection($row['section']) . ' ' . $label;
        }

        return $label;
    }

    private static function formatSection(string $section): string
    {
        return match ($section) {
            'php_server' => 'PHP Server',
            'redis' => 'Redis',
            default => ucwords(str_replace('_', ' ', $section)),
        };
    }

    private static function formatValue(mixed $value, string $setting = ''): string
    {
        if ($value === null) {
            return 'null';
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_scalar($value)) {
            if (is_int($value)) {
                if (in_array($setting, ['db', 'port', 'redis_port', 'seed'], true)) {
                    return (string) $value;
                }

                if (str_ends_with($setting, '_us')) {
                    return number_format($value) . 'us';
                }

                if (str_ends_with($setting, '_ms')) {
                    return number_format($value) . 'ms';
                }

                if (str_ends_with($setting, '_seconds')) {
                    return number_format($value) . 's';
                }

                return number_format($value);
            }

            return (string) $value;
        }

        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private static function signalName(int $signal): string
    {
        return match ($signal) {
            2 => 'SIGINT',
            3 => 'SIGQUIT',
            6 => 'SIGABRT',
            9 => 'SIGKILL',
            15 => 'SIGTERM',
            default => 'SIG' . $signal,
        };
    }
}

final class RingBuffer
{
    /** @var list<mixed> */
    private array $items = [];

    public function __construct(private readonly int $limit)
    {
    }

    public function push(mixed $item): void
    {
        $this->items[] = $item;

        if (count($this->items) > $this->limit) {
            array_shift($this->items);
        }
    }

    /**
     * @return list<mixed>
     */
    public function all(): array
    {
        return $this->items;
    }
}

final class Rng
{
    private Randomizer $randomizer;

    public function __construct(int $seed)
    {
        $this->randomizer = new Randomizer(new Mt19937($seed));
    }

    public function int(int $min, int $max): int
    {
        return $this->randomizer->getInt($min, $max);
    }

    public function float(): float
    {
        return $this->int(0, 1_000_000_000) / 1_000_000_000;
    }

    /**
     * @template T
     * @param list<T> $items
     * @return T
     */
    public function pick(array $items): mixed
    {
        if ($items === []) {
            throw new FuzzerException('Cannot pick from an empty list');
        }

        return $items[$this->int(0, count($items) - 1)];
    }

    /**
     * @template T
     * @param list<T> $items
     * @return list<T>
     */
    public function shuffled(array $items): array
    {
        for ($i = count($items) - 1; $i > 0; $i--) {
            $j = $this->int(0, $i);
            [$items[$i], $items[$j]] = [$items[$j], $items[$i]];
        }

        return $items;
    }

    /**
     * @param array<int, int> $weights
     */
    public function weighted(array $weights): int
    {
        $total = array_sum($weights);
        $pick = $this->int(1, $total);
        $seen = 0;

        foreach ($weights as $value => $weight) {
            $seen += $weight;

            if ($pick <= $seen) {
                return $value;
            }
        }

        return array_key_first($weights);
    }
}

final class RedisClient
{
    /** @var resource */
    private mixed $socket;

    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly int $db,
        private readonly int $timeoutMs = 1000,
    ) {
        $this->connect();

        if ($this->db !== 0) {
            $this->command(['SELECT', (string) $this->db]);
        }
    }

    public function ping(): void
    {
        $reply = $this->command(['PING']);

        if ($reply !== 'PONG') {
            throw new FuzzerException('Unexpected Redis PING reply');
        }
    }

    public function set(string $key, string $value): void
    {
        $reply = $this->command(['SET', $key, $value]);

        if ($reply !== 'OK') {
            throw new FuzzerException("Redis SET failed for {$key}");
        }
    }

    public function incr(string $key): int
    {
        $reply = $this->command(['INCR', $key]);

        if (!is_int($reply)) {
            throw new FuzzerException("Redis INCR returned a non-integer for {$key}");
        }

        return $reply;
    }

    public function incrBy(string $key, int $amount): int
    {
        $reply = $this->command(['INCRBY', $key, (string) $amount]);

        if (!is_int($reply)) {
            throw new FuzzerException("Redis INCRBY returned a non-integer for {$key}");
        }

        return $reply;
    }

    public function flushDb(): void
    {
        $reply = $this->command(['FLUSHDB']);

        if ($reply !== 'OK') {
            throw new FuzzerException('Redis FLUSHDB failed');
        }
    }

    public function flushAll(): void
    {
        $reply = $this->command(['FLUSHALL']);

        if ($reply !== 'OK') {
            throw new FuzzerException('Redis FLUSHALL failed');
        }
    }

    public function get(string $key): ?string
    {
        $reply = $this->command(['GET', $key]);

        if ($reply === null || is_string($reply)) {
            return $reply;
        }

        throw new FuzzerException("Redis GET returned an unexpected type for {$key}");
    }

    /**
     * @param list<string> $keys
     */
    public function del(array $keys): void
    {
        if ($keys === []) {
            return;
        }

        $this->command(array_merge(['DEL'], $keys));
    }

    /**
     * @param list<string> $parts
     */
    public function command(array $parts): mixed
    {
        $payload = '*' . count($parts) . "\r\n";

        foreach ($parts as $part) {
            $payload .= '$' . strlen($part) . "\r\n" . $part . "\r\n";
        }

        $this->write($payload);

        return $this->readResponse();
    }

    private function connect(): void
    {
        $timeout = $this->timeoutMs / 1000;
        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client(
            "tcp://{$this->host}:{$this->port}",
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
        );

        if ($socket === false) {
            throw new FuzzerException("Could not connect to Redis at {$this->host}:{$this->port}: {$errstr}");
        }

        stream_set_timeout($socket, intdiv($this->timeoutMs, 1000), ($this->timeoutMs % 1000) * 1000);
        $this->socket = $socket;
    }

    private function write(string $payload): void
    {
        $remaining = $payload;

        while ($remaining !== '') {
            $written = fwrite($this->socket, $remaining);

            if ($written === false || $written === 0) {
                throw new FuzzerException('Failed writing to Redis');
            }

            $remaining = substr($remaining, $written);
        }
    }

    private function readResponse(): mixed
    {
        $prefix = fgetc($this->socket);

        if ($prefix === false) {
            throw new FuzzerException('Redis closed the connection');
        }

        $line = $this->readLine();

        return match ($prefix) {
            '+' => $line,
            '-' => throw new FuzzerException("Redis error: {$line}"),
            ':' => (int) $line,
            '$' => $this->readBulk((int) $line),
            '*' => $this->readArray((int) $line),
            default => throw new FuzzerException("Unsupported Redis response prefix: {$prefix}"),
        };
    }

    private function readLine(): string
    {
        $line = fgets($this->socket);

        if ($line === false) {
            throw new FuzzerException('Failed reading from Redis');
        }

        return rtrim($line, "\r\n");
    }

    private function readBulk(int $length): ?string
    {
        if ($length < 0) {
            return null;
        }

        $data = '';
        $remaining = $length + 2;

        while (strlen($data) < $remaining) {
            $chunk = fread($this->socket, $remaining - strlen($data));

            if ($chunk === false || $chunk === '') {
                throw new FuzzerException('Failed reading Redis bulk string');
            }

            $data .= $chunk;
        }

        return substr($data, 0, $length);
    }

    /**
     * @return list<mixed>|null
     */
    private function readArray(int $length): ?array
    {
        if ($length < 0) {
            return null;
        }

        $items = [];

        for ($i = 0; $i < $length; $i++) {
            $items[] = $this->readResponse();
        }

        return $items;
    }
}

final class RedisServerProcess
{
    private Process $process;
    private string $runtimeDir;

    public function __construct(
        private readonly Config $config,
        private readonly LoggerInterface $logger,
        string $runId,
    ) {
        $safeRunId = preg_replace('/[^A-Za-z0-9_.:-]/', '-', $runId) ?: bin2hex(random_bytes(6));
        $this->runtimeDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'relay-cache-fuzzer-redis-' . $safeRunId;
    }

    public function start(): void
    {
        if ($this->config->redisServer === null) {
            return;
        }

        if (!is_dir($this->runtimeDir) && !mkdir($this->runtimeDir, 0777, true) && !is_dir($this->runtimeDir)) {
            throw new FuzzerException("Could not create Redis runtime directory {$this->runtimeDir}");
        }

        $command = [
            $this->config->redisServer,
            '--bind', $this->config->redisHost,
            '--port', (string) $this->config->redisPort,
            '--daemonize', 'no',
            '--save', '',
            '--appendonly', 'no',
            '--protected-mode', 'no',
            '--dir', $this->runtimeDir,
            '--dbfilename', 'dump.rdb',
        ];

        $this->process = new Process($command, dirname(__DIR__));
        $this->process->setTimeout(null);
        $this->logger->info('starting ephemeral Redis server', [
            'host' => $this->config->redisHost,
            'port' => $this->config->redisPort,
            'runtime_dir' => $this->runtimeDir,
        ]);
        $this->logger->debug('Redis command line', ['command' => $this->process->getCommandLine()]);
        $this->process->start();
        $this->waitUntilReady();
    }

    public function stop(): void
    {
        if ($this->config->redisServer === null || !isset($this->process)) {
            return;
        }

        if ($this->process->isRunning()) {
            $this->logger->info('stopping ephemeral Redis server', ['pid' => $this->process->getPid()]);

            try {
                (new RedisClient($this->config->redisHost, $this->config->redisPort, 0, $this->config->requestTimeoutMs))
                    ->command(['SHUTDOWN', 'NOSAVE']);
            } catch (Throwable) {
            }

            $this->process->stop(1.0, 15);
        }

        if (!$this->config->keepTemp && is_dir($this->runtimeDir)) {
            self::removeTree($this->runtimeDir);
        }
    }

    private function waitUntilReady(): void
    {
        $deadline = microtime(true) + max(2.0, $this->config->requestTimeoutMs / 1000 * 5);
        $lastError = null;

        while (microtime(true) < $deadline) {
            if (!$this->process->isRunning()) {
                throw new FuzzerException('Ephemeral Redis server exited before becoming ready');
            }

            try {
                (new RedisClient($this->config->redisHost, $this->config->redisPort, 0, $this->config->requestTimeoutMs))->ping();
                $this->logger->debug('ephemeral Redis ping succeeded');
                return;
            } catch (Throwable $e) {
                $lastError = $e->getMessage();
                usleep(20_000);
            }
        }

        throw new FuzzerException('Ephemeral Redis server did not become ready' . ($lastError === null ? '' : ": {$lastError}"));
    }

    private static function removeTree(string $path): void
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                rmdir($item->getPathname());
                continue;
            }

            unlink($item->getPathname());
        }

        rmdir($path);
    }
}

final class HttpClient
{
    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly int $timeoutMs,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function getJson(string $path): array
    {
        $timeout = $this->timeoutMs / 1000;
        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client(
            "tcp://{$this->host}:{$this->port}",
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
        );

        if ($socket === false) {
            throw new RequestException("HTTP connect failed: {$errstr}", true);
        }

        stream_set_timeout($socket, intdiv($this->timeoutMs, 1000), ($this->timeoutMs % 1000) * 1000);

        $request = "GET {$path} HTTP/1.1\r\n"
            . "Host: {$this->host}:{$this->port}\r\n"
            . "Connection: close\r\n"
            . "Accept: application/json\r\n\r\n";

        if (fwrite($socket, $request) === false) {
            self::closeSocket($socket);
            throw new RequestException('HTTP request write failed');
        }

        $response = '';

        while (!feof($socket)) {
            $chunk = fread($socket, 8192);

            if ($chunk === false) {
                self::closeSocket($socket);
                throw new RequestException('HTTP response read failed');
            }

            if ($chunk === '') {
                $meta = stream_get_meta_data($socket);
                self::closeSocket($socket);

                if ($meta['timed_out'] === true) {
                    throw new RequestException('HTTP request timed out', true);
                }

                break;
            }

            $response .= $chunk;
        }

        self::closeSocket($socket);

        [$head, $body] = array_pad(explode("\r\n\r\n", $response, 2), 2, '');
        $statusLine = strtok($head, "\r\n");

        if (!is_string($statusLine) || !preg_match('/^HTTP\/\d(?:\.\d)?\s+(\d+)/', $statusLine, $matches)) {
            throw new RequestException('Malformed HTTP response');
        }

        $status = (int) $matches[1];
        $decoded = json_decode($body, true);

        if (!is_array($decoded)) {
            throw new RequestException("Invalid JSON response with status {$status}: {$body}");
        }

        if ($status < 200 || $status >= 300) {
            $message = isset($decoded['error']) && is_string($decoded['error'])
                ? $decoded['error']
                : "HTTP {$status}";

            throw new RequestException($message);
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param resource $socket
     */
    private static function closeSocket(mixed $socket): void
    {
        if (is_resource($socket)) {
            fclose($socket);
        }
    }
}

final class ServerProcess
{
    private Process $process;
    private ?Process $nginxProcess = null;
    private RingBuffer $stdout;
    private RingBuffer $stderr;
    private string $runtimeDir;
    /** @var array<string, mixed>|null */
    private ?array $startupProcessMetadata = null;

    public function __construct(
        private readonly Config $config,
        private readonly LoggerInterface $logger,
        private readonly ?string $rrTraceDir = null,
        ?string $runId = null,
    ) {
        $this->stdout = new RingBuffer(200);
        $this->stderr = new RingBuffer(200);
        $safeRunId = preg_replace('/[^A-Za-z0-9_.:-]/', '-', $runId ?? bin2hex(random_bytes(6))) ?: bin2hex(random_bytes(6));
        $this->runtimeDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'relay-cache-fuzzer-' . $safeRunId;
    }

    public function start(): void
    {
        if ($this->config->fpm) {
            $this->startFpm();
            return;
        }

        $this->startCliServer();
    }

    private function startCliServer(): void
    {
        if ($this->config->captureRelayLogLevel !== null) {
            $this->prepareRuntimeDirectory();
        }

        $router = dirname(__DIR__) . '/router.php';
        $command = [
            $this->config->php,
            '-d', 'relay.max_endpoint_dbs=' . $this->config->relayMaxEndpointDbs,
            '-d', 'relay.max_db_writers=' . $this->config->relayMaxDbWriters,
            '-d', 'relay.cache=1',
        ];

        $command = array_merge($command, $this->relayLogIniArguments(), [
            '-S', $this->config->host . ':' . $this->config->port,
            $router,
        ]);
        $env = [
            'PHP_CLI_SERVER_WORKERS' => (string) $this->config->workers,
            'RELAY_FUZZ_CLIENT' => $this->config->client,
            'RELAY_FUZZ_REDIS_HOST' => $this->config->redisHost,
            'RELAY_FUZZ_REDIS_PORT' => (string) $this->config->redisPort,
            'RELAY_FUZZ_REDIS_DB' => (string) $this->config->redisDb,
        ];

        if ($this->config->rr) {
            $command = array_merge(['rr', 'record'], $command);

            if ($this->rrTraceDir !== null) {
                $env['_RR_TRACE_DIR'] = $this->rrTraceDir;
            }
        }

        $this->process = new Process(
            $command,
            dirname(__DIR__),
            $env,
        );
        $this->process->setTimeout(null);
        $this->logger->info('starting PHP CLI server', [
            'host' => $this->config->host,
            'port' => $this->config->port,
            'workers' => $this->config->workers,
            'rr' => $this->config->rr,
            'rr_trace_dir' => $this->rrTraceDir,
            'client' => $this->config->client,
            'relay_logfile' => $this->relayLogFile(),
        ]);
        $this->logger->debug('server command line', ['command' => $this->process->getCommandLine()]);
        $this->process->start();

        $this->logger->debug('server parent started', ['pid' => $this->process->getPid()]);
        $this->captureStartupProcessMetadata();
    }

    private function startFpm(): void
    {
        $this->prepareFpmRuntimeDirectory();
        $socketPath = $this->runtimeDir . DIRECTORY_SEPARATOR . 'php-fpm.sock';
        $pidPath = $this->runtimeDir . DIRECTORY_SEPARATOR . 'php-fpm.pid';
        $fpmConfig = $this->runtimeDir . DIRECTORY_SEPARATOR . 'php-fpm.conf';
        $poolConfig = $this->runtimeDir . DIRECTORY_SEPARATOR . 'pool.conf';
        $nginxConfig = $this->runtimeDir . DIRECTORY_SEPARATOR . 'nginx.conf';

        $this->writeFpmConfig($fpmConfig, $poolConfig, $pidPath, $socketPath);
        $this->writeNginxConfig($nginxConfig, $socketPath);

        $env = [
            'RELAY_FUZZ_CLIENT' => $this->config->client,
            'RELAY_FUZZ_REDIS_HOST' => $this->config->redisHost,
            'RELAY_FUZZ_REDIS_PORT' => (string) $this->config->redisPort,
            'RELAY_FUZZ_REDIS_DB' => (string) $this->config->redisDb,
        ];
        $command = [
            $this->config->phpFpm,
            '-F',
            '-y', $fpmConfig,
            '-d', 'relay.max_endpoint_dbs=' . $this->config->relayMaxEndpointDbs,
            '-d', 'relay.max_db_writers=' . $this->config->relayMaxDbWriters,
            '-d', 'relay.cache=1',
        ];
        $command = array_merge($command, $this->relayLogIniArguments());

        $this->process = new Process($command, dirname(__DIR__), $env);
        $this->process->setTimeout(null);
        $this->logger->info('starting php-fpm', [
            'workers' => $this->config->workers,
            'socket' => $socketPath,
            'runtime_dir' => $this->runtimeDir,
            'client' => $this->config->client,
            'relay_logfile' => $this->relayLogFile(),
        ]);
        $this->logger->debug('php-fpm command line', ['command' => $this->process->getCommandLine()]);
        $this->process->start();

        $nginxCommand = [$this->config->nginx, '-p', $this->runtimeDir, '-c', $nginxConfig, '-g', 'daemon off;'];
        $this->nginxProcess = new Process($nginxCommand, dirname(__DIR__));
        $this->nginxProcess->setTimeout(null);
        $this->logger->info('starting nginx', [
            'host' => $this->config->host,
            'port' => $this->config->port,
            'runtime_dir' => $this->runtimeDir,
        ]);
        $this->logger->debug('nginx command line', ['command' => $this->nginxProcess->getCommandLine()]);
        $this->nginxProcess->start();
        $this->captureStartupProcessMetadata();
    }

    private function prepareFpmRuntimeDirectory(): void
    {
        $this->prepareRuntimeDirectory();

        foreach (['logs', 'client-body'] as $dir) {
            $path = $this->runtimeDir . DIRECTORY_SEPARATOR . $dir;

            if (!is_dir($path) && !mkdir($path, 0777, true) && !is_dir($path)) {
                throw new FuzzerException("Could not create FPM runtime subdirectory {$path}");
            }
        }
    }

    private function prepareRuntimeDirectory(): void
    {
        if (!is_dir($this->runtimeDir) && !mkdir($this->runtimeDir, 0777, true) && !is_dir($this->runtimeDir)) {
            throw new FuzzerException("Could not create server runtime directory {$this->runtimeDir}");
        }
    }

    /**
     * @return list<string>
     */
    private function relayLogIniArguments(): array
    {
        if ($this->config->captureRelayLogLevel === null) {
            return [];
        }

        $relayLogFile = $this->relayLogFile();
        if ($relayLogFile === null) {
            return [];
        }

        return [
            '-d', 'relay.loglevel=' . $this->config->captureRelayLogLevel,
            '-d', 'relay.logfile=' . $relayLogFile,
        ];
    }

    private function writeFpmConfig(string $fpmConfig, string $poolConfig, string $pidPath, string $socketPath): void
    {
        $globalStub = $this->config->fpmConfStub === null ? '' : trim((string) file_get_contents($this->config->fpmConfStub));
        $poolStub = $this->config->fpmPoolConfStub === null ? '' : trim((string) file_get_contents($this->config->fpmPoolConfStub));
        $globalExtra = $globalStub === '' ? '' : "\n; user fpm-conf-stub\n{$globalStub}\n";
        $poolExtra = $poolStub === '' ? '' : "\n; user fpm-pool-conf-stub\n{$poolStub}\n";

        $global = <<<CONF
[global]
pid = {$pidPath}
error_log = {$this->runtimeDir}/logs/php-fpm-error.log
log_level = notice
daemonize = no
{$globalExtra}
include = {$poolConfig}

CONF;
        $pool = <<<CONF
[relay_fuzz]
listen = {$socketPath}
listen.mode = 0666
pm = static
pm.max_children = {$this->config->workers}
catch_workers_output = yes
clear_env = no
env[RELAY_FUZZ_CLIENT] = {$this->config->client}
env[RELAY_FUZZ_REDIS_HOST] = {$this->config->redisHost}
env[RELAY_FUZZ_REDIS_PORT] = {$this->config->redisPort}
env[RELAY_FUZZ_REDIS_DB] = {$this->config->redisDb}
{$poolExtra}

CONF;

        file_put_contents($fpmConfig, $global);
        file_put_contents($poolConfig, $pool);
    }

    private function writeNginxConfig(string $nginxConfig, string $socketPath): void
    {
        $router = dirname(__DIR__) . '/router.php';
        $root = dirname(__DIR__);
        $host = $this->config->host;
        $port = $this->config->port;

        $config = <<<CONF
worker_processes 1;
pid {$this->runtimeDir}/nginx.pid;
error_log {$this->runtimeDir}/logs/nginx-error.log info;

events {
    worker_connections 128;
}

http {
    access_log {$this->runtimeDir}/logs/nginx-access.log;
    client_body_temp_path {$this->runtimeDir}/client-body;

    server {
        listen {$host}:{$port};
        server_name relay-cache-fuzzer;
        root {$root};

        location / {
            fastcgi_pass unix:{$socketPath};
            fastcgi_param GATEWAY_INTERFACE CGI/1.1;
            fastcgi_param SERVER_SOFTWARE nginx;
            fastcgi_param REMOTE_ADDR \$remote_addr;
            fastcgi_param REMOTE_PORT \$remote_port;
            fastcgi_param SERVER_ADDR \$server_addr;
            fastcgi_param SERVER_PORT \$server_port;
            fastcgi_param SERVER_NAME \$server_name;
            fastcgi_param SERVER_PROTOCOL \$server_protocol;
            fastcgi_param SCRIPT_FILENAME {$router};
            fastcgi_param SCRIPT_NAME /router.php;
            fastcgi_param DOCUMENT_ROOT {$root};
            fastcgi_param REQUEST_URI \$request_uri;
            fastcgi_param QUERY_STRING \$query_string;
            fastcgi_param REQUEST_METHOD \$request_method;
            fastcgi_param CONTENT_TYPE \$content_type;
            fastcgi_param CONTENT_LENGTH \$content_length;
        }
    }
}

CONF;

        file_put_contents($nginxConfig, $config);
    }

    public function drain(): void
    {
        if (isset($this->process)) {
            $this->pushLines($this->stdout, $this->process->getIncrementalOutput(), $this->config->fpm ? 'php-fpm stdout' : 'stdout');
            $this->pushLines($this->stderr, $this->process->getIncrementalErrorOutput(), $this->config->fpm ? 'php-fpm stderr' : 'stderr');
        }

        if ($this->nginxProcess instanceof Process) {
            $this->pushLines($this->stdout, $this->nginxProcess->getIncrementalOutput(), 'nginx stdout');
            $this->pushLines($this->stderr, $this->nginxProcess->getIncrementalErrorOutput(), 'nginx stderr');
        }
    }

    public function isRunning(): bool
    {
        $this->drain();

        if (!$this->process->isRunning()) {
            return false;
        }

        return !$this->nginxProcess instanceof Process || $this->nginxProcess->isRunning();
    }

    public function parentPid(): ?int
    {
        return $this->process->getPid();
    }

    /**
     * @return array<string, mixed>|null
     */
    public function startupProcessMetadata(): ?array
    {
        return $this->startupProcessMetadata;
    }

    public function startupProcessMetadataText(): string
    {
        $metadata = $this->startupProcessMetadata;

        if ($metadata === null) {
            return "Server process metadata was not captured.\n";
        }

        $lines = [
            'Server Process Metadata',
            '=======================',
            '',
            'Captured At : ' . (string) ($metadata['captured_at'] ?? 'unknown'),
            'Transport   : ' . (string) ($metadata['transport'] ?? 'unknown'),
            'Workers     : ' . (string) ($metadata['expected_workers'] ?? 'unknown'),
            '',
        ];

        $php = $metadata['php_server'] ?? null;
        if (is_array($php)) {
            $lines[] = 'PHP Server';
            $lines[] = '----------';
            $lines = array_merge($lines, self::formatProcessTreeLines($php));
            $lines[] = '';
        }

        $nginx = $metadata['nginx'] ?? null;
        if (is_array($nginx)) {
            $lines[] = 'Nginx';
            $lines[] = '-----';
            $lines = array_merge($lines, self::formatProcessTreeLines($nginx));
            $lines[] = '';
        }

        $workers = $metadata['php_worker_pids'] ?? [];
        if (is_array($workers)) {
            $lines[] = 'PHP Worker PIDs';
            $lines[] = '---------------';
            $lines[] = $workers === [] ? '(none captured)' : implode(', ', array_map('strval', $workers));
            $lines[] = '';
        }

        $notes = $metadata['notes'] ?? [];
        if (is_array($notes) && $notes !== []) {
            $lines[] = 'Notes';
            $lines[] = '-----';

            foreach ($notes as $note) {
                $lines[] = '- ' . (string) $note;
            }

            $lines[] = '';
        }

        return implode("\n", $lines);
    }

    public function commandLine(): string
    {
        if ($this->nginxProcess instanceof Process) {
            return 'php-fpm: ' . $this->process->getCommandLine() . "\nnginx: " . $this->nginxProcess->getCommandLine();
        }

        return $this->process->getCommandLine();
    }

    /**
     * @return array{stdout: list<mixed>, stderr: list<mixed>}
     */
    public function tails(): array
    {
        $this->drain();

        return [
            'stdout' => $this->stdout->all(),
            'stderr' => $this->stderr->all(),
        ];
    }

    public function stop(): bool
    {
        if (!isset($this->process) || !$this->process->isRunning()) {
            if ($this->nginxProcess instanceof Process && $this->nginxProcess->isRunning()) {
                $this->nginxProcess->stop(0.0, 15);
            }

            return true;
        }

        if ($this->nginxProcess instanceof Process && $this->nginxProcess->isRunning()) {
            $this->logger->info('stopping nginx', ['pid' => $this->nginxProcess->getPid()]);
            $this->nginxProcess->stop(1.0, 15);
        }

        $this->logger->info($this->config->fpm ? 'stopping php-fpm' : 'stopping PHP CLI server', ['parent_pid' => $this->process->getPid()]);

        try {
            $this->process->signal(15);
        } catch (Throwable) {
            return true;
        }

        $deadline = microtime(true) + 1.0;

        while ($this->process->isRunning() && microtime(true) < $deadline) {
            $this->drain();
            usleep(1000);
        }

        if (!$this->process->isRunning()) {
            return true;
        }

        $this->logger->warning($this->config->fpm ? 'php-fpm did not stop after SIGTERM' : 'PHP CLI server did not stop after SIGTERM', ['parent_pid' => $this->process->getPid()]);
        $this->process->stop(0.0, 15);

        return false;
    }

    public function crashingSignalName(): ?string
    {
        if (!isset($this->process) || !$this->process->isTerminated()) {
            return null;
        }

        try {
            if ($this->process->hasBeenSignaled()) {
                return self::crashingSignalNameForNumber($this->process->getTermSignal());
            }
        } catch (Throwable) {
            return null;
        }

        $exitCode = $this->process->getExitCode();

        if ($exitCode !== null && $exitCode >= 128) {
            return self::crashingSignalNameForNumber($exitCode - 128);
        }

        return null;
    }

    private static function crashingSignalNameForNumber(int $signal): ?string
    {
        return match ($signal) {
            4 => 'SIGILL',
            6 => 'SIGABRT',
            7 => 'SIGBUS',
            8 => 'SIGFPE',
            11 => 'SIGSEGV',
            default => null,
        };
    }

    /**
     * @return array{stdout: string, stderr: string}
     */
    public function outputText(): array
    {
        $tails = $this->tails();

        return [
            'stdout' => implode("\n", array_map('strval', $tails['stdout'])) . ($tails['stdout'] === [] ? '' : "\n"),
            'stderr' => implode("\n", array_map('strval', $tails['stderr'])) . ($tails['stderr'] === [] ? '' : "\n"),
        ];
    }

    public function runtimeDirectory(): ?string
    {
        return $this->config->fpm || $this->config->captureRelayLogLevel !== null ? $this->runtimeDir : null;
    }

    public function relayLogFile(): ?string
    {
        return $this->config->captureRelayLogLevel === null ? null : $this->runtimeDir . DIRECTORY_SEPARATOR . 'relay.log';
    }

    public function cleanupRuntimeDirectory(): void
    {
        if (
            $this->runtimeDirectory() === null
            || $this->config->keepTemp
            || $this->config->captureRelayLogLevel !== null
            || !is_dir($this->runtimeDir)
        ) {
            return;
        }

        self::removeTree($this->runtimeDir);
    }

    public function copyRuntimeDirectory(string $destination): void
    {
        if ($this->runtimeDirectory() === null || !is_dir($this->runtimeDir)) {
            return;
        }

        self::copyTree($this->runtimeDir, $destination);
    }

    private static function copyTree(string $source, string $destination): void
    {
        if (!is_dir($destination) && !mkdir($destination, 0777, true) && !is_dir($destination)) {
            throw new FuzzerException("Could not create runtime bundle directory {$destination}");
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
        );

        foreach ($iterator as $item) {
            $target = $destination . DIRECTORY_SEPARATOR . $iterator->getSubPathName();

            if ($item->isDir()) {
                if (!is_dir($target) && !mkdir($target, 0777, true) && !is_dir($target)) {
                    throw new FuzzerException("Could not create runtime bundle directory {$target}");
                }

                continue;
            }

            if ($item->isFile() && !copy($item->getPathname(), $target)) {
                throw new FuzzerException("Could not copy runtime file {$item->getPathname()}");
            }
        }
    }

    private static function removeTree(string $path): void
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                rmdir($item->getPathname());
                continue;
            }

            unlink($item->getPathname());
        }

        rmdir($path);
    }

    private function pushLines(RingBuffer $buffer, string $chunk, string $stream = 'server'): void
    {
        foreach (preg_split('/\r?\n/', $chunk) ?: [] as $line) {
            if ($line !== '') {
                $buffer->push($line);
                $this->logger->debug('server output', ['stream' => $stream, 'line' => $line]);
            }
        }
    }

    private function captureStartupProcessMetadata(): void
    {
        $deadline = microtime(true) + 2.0;
        $metadata = null;

        do {
            $metadata = $this->buildStartupProcessMetadata();

            if (count($metadata['php_worker_pids']) >= $this->config->workers) {
                break;
            }

            usleep(20_000);
        } while (microtime(true) < $deadline);

        if (count($metadata['php_worker_pids']) < $this->config->workers) {
            $metadata['notes'][] = 'Captured fewer PHP worker PIDs than configured workers before startup snapshot timeout.';
        }

        $this->startupProcessMetadata = $metadata;
        $this->logger->debug('captured startup server process metadata', [
            'php_worker_pids' => $metadata['php_worker_pids'],
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function buildStartupProcessMetadata(): array
    {
        $phpPid = $this->process->getPid();
        $nginxPid = $this->nginxProcess instanceof Process ? $this->nginxProcess->getPid() : null;
        $notes = [];

        if (!is_dir('/proc')) {
            $notes[] = '/proc is not available; process tree details are limited.';
        }

        $phpTree = $phpPid === null ? null : self::processTree($phpPid);
        $nginxTree = $nginxPid === null ? null : self::processTree($nginxPid);
        $workerPids = $phpTree === null ? [] : self::phpWorkerPids($phpTree, $phpPid);

        if ($phpPid === null) {
            $notes[] = 'PHP server master PID was not available from Symfony Process.';
        }

        return [
            'captured_at' => date(DATE_ATOM),
            'captured_at_unix' => sprintf('%.6f', microtime(true)),
            'transport' => $this->config->fpm ? 'fpm' : 'cli',
            'expected_workers' => $this->config->workers,
            'php_server' => $phpTree,
            'nginx' => $nginxTree,
            'php_worker_pids' => $workerPids,
            'notes' => $notes,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function processTree(int $pid): array
    {
        $node = self::processInfo($pid);
        $children = self::childrenOf($pid);

        sort($children);

        $node['children'] = array_map(self::processTree(...), $children);

        return $node;
    }

    /**
     * @return array<string, mixed>
     */
    private static function processInfo(int $pid): array
    {
        $info = [
            'pid' => $pid,
            'exists' => is_dir("/proc/{$pid}"),
        ];

        $stat = @file_get_contents("/proc/{$pid}/stat");
        if (is_string($stat) && preg_match('/^(\d+)\s+\((.*)\)\s+([A-Z])\s+(\d+)/', $stat, $matches)) {
            $info['comm'] = $matches[2];
            $info['state'] = $matches[3];
            $info['ppid'] = (int) $matches[4];
        }

        $cmdline = @file_get_contents("/proc/{$pid}/cmdline");
        if (is_string($cmdline)) {
            $parts = array_values(array_filter(explode("\0", rtrim($cmdline, "\0")), static fn (string $part): bool => $part !== ''));
            $info['argv'] = $parts;
            $info['command'] = implode(' ', $parts);
        }

        $exe = @readlink("/proc/{$pid}/exe");
        if (is_string($exe)) {
            $info['exe'] = $exe;
        }

        $cwd = @readlink("/proc/{$pid}/cwd");
        if (is_string($cwd)) {
            $info['cwd'] = $cwd;
        }

        $status = @file("/proc/{$pid}/status", FILE_IGNORE_NEW_LINES);
        if (is_array($status)) {
            foreach ($status as $line) {
                if (preg_match('/^(Name|State|PPid|Threads|VmRSS|VmSize):\s*(.+)$/', $line, $matches)) {
                    $info['status'][$matches[1]] = $matches[2];
                }
            }
        }

        return $info;
    }

    /**
     * @return list<int>
     */
    private static function childrenOf(int $pid): array
    {
        $childrenFile = "/proc/{$pid}/task/{$pid}/children";
        $children = @file_get_contents($childrenFile);

        if (is_string($children)) {
            $children = trim($children);

            if ($children === '') {
                return [];
            }

            return array_map('intval', preg_split('/\s+/', $children) ?: []);
        }

        $pids = [];
        foreach (glob('/proc/[0-9]*/stat') ?: [] as $statFile) {
            $stat = @file_get_contents($statFile);

            if (is_string($stat) && preg_match('/^(\d+)\s+\(.*\)\s+[A-Z]\s+(\d+)/', $stat, $matches) && (int) $matches[2] === $pid) {
                $pids[] = (int) $matches[1];
            }
        }

        return $pids;
    }

    /**
     * @param array<string, mixed> $tree
     * @return list<int>
     */
    private static function phpWorkerPids(array $tree, int $rootPid): array
    {
        $pids = [];

        foreach (self::flattenProcessTree($tree) as $node) {
            $pid = $node['pid'] ?? null;

            if (!is_int($pid) || $pid === $rootPid) {
                continue;
            }

            if (self::isPhpProcess($node) && !self::hasPhpChild($node)) {
                $pids[] = $pid;
            }
        }

        sort($pids);

        return $pids;
    }

    /**
     * @param array<string, mixed> $node
     */
    private static function isPhpProcess(array $node): bool
    {
        $command = strtolower((string) ($node['command'] ?? $node['comm'] ?? ''));
        $exe = strtolower((string) ($node['exe'] ?? ''));

        return str_contains($command, 'php') || str_contains($exe, 'php');
    }

    /**
     * @param array<string, mixed> $node
     */
    private static function hasPhpChild(array $node): bool
    {
        foreach (($node['children'] ?? []) as $child) {
            if (is_array($child) && self::isPhpProcess($child)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $tree
     * @return list<array<string, mixed>>
     */
    private static function flattenProcessTree(array $tree): array
    {
        $nodes = [$tree];

        foreach (($tree['children'] ?? []) as $child) {
            if (is_array($child)) {
                $nodes = array_merge($nodes, self::flattenProcessTree($child));
            }
        }

        return $nodes;
    }

    /**
     * @param array<string, mixed> $tree
     * @return list<string>
     */
    private static function formatProcessTreeLines(array $tree, string $prefix = ''): array
    {
        $pid = (string) ($tree['pid'] ?? '?');
        $ppid = array_key_exists('ppid', $tree) ? ' ppid=' . (string) $tree['ppid'] : '';
        $state = array_key_exists('state', $tree) ? ' state=' . (string) $tree['state'] : '';
        $command = (string) ($tree['command'] ?? $tree['comm'] ?? '(unknown command)');
        $lines = [$prefix . 'pid=' . $pid . $ppid . $state . ' cmd=' . $command];

        if (isset($tree['exe'])) {
            $lines[] = $prefix . '  exe=' . (string) $tree['exe'];
        }

        if (isset($tree['cwd'])) {
            $lines[] = $prefix . '  cwd=' . (string) $tree['cwd'];
        }

        foreach (($tree['children'] ?? []) as $child) {
            if (is_array($child)) {
                $lines = array_merge($lines, self::formatProcessTreeLines($child, $prefix . '  '));
            }
        }

        return $lines;
    }
}

final class ServerProcessMetadataFiles
{
    public static function write(ServerProcess $server, string $bundlePath): void
    {
        $metadata = $server->startupProcessMetadata();

        file_put_contents($bundlePath . DIRECTORY_SEPARATOR . 'server-processes.txt', $server->startupProcessMetadataText());

        if ($metadata !== null) {
            file_put_contents($bundlePath . DIRECTORY_SEPARATOR . 'server-processes.json', json_encode($metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
        }
    }
}

final class Fuzzer
{
    private Config $config;
    private Rng $rng;
    private RedisClient $redis;
    private HttpClient $http;
    private ServerProcess $server;
    private ?RedisServerProcess $redisServer = null;
    private LoggerInterface $logger;
    private string $runId;
    private ?string $failurePath = null;
    private ?string $failureType = null;
    private float $lastSuccessAt;

    /** @var array<int, true> */
    private array $observedPids = [];

    /** @var array<int, list<string>> */
    private array $keysByPid = [];

    /** @var array<string, int> */
    private array $expected = [];

    /** @var array<string, int> */
    private array $keyOwner = [];

    /** @var list<array<string, mixed>> */
    private array $events = [];

    /** @var array<int, true> */
    private array $killedPids = [];

    /** @var array<int, int> */
    private array $workerCommandCounts = [];

    /** @var array<string, int> */
    private array $stats = [
        'total_requests' => 0,
        'successful_requests' => 0,
        'failed_requests' => 0,
        'request_timeouts' => 0,
        'stale_observations' => 0,
        'persistent_stale_failures' => 0,
        'workers_discovered' => 0,
        'workers_killed' => 0,
        'iterations' => 0,
    ];

    private RingBuffer $lastRequests;
    private RingBuffer $lastMutations;
    private RingBuffer $lastStale;

    public function __construct(Config $config)
    {
        if ($config->port === 0) {
            $config = $config->withPort(self::pickFreePort($config->host));
        }
        if ($config->redisServer !== null && $config->redisPort === 0) {
            $config = $config->withRedisPort(self::pickFreePort($config->redisHost));
        }

        $this->config = $config;
        $this->logger = LogFactory::create($this->config);
        $this->rng = new Rng($this->config->seed);
        $this->runId = $this->config->runId ?? dechex($this->config->seed) . '-' . bin2hex(random_bytes(3));
        $this->lastRequests = new RingBuffer(100);
        $this->lastMutations = new RingBuffer(100);
        $this->lastStale = new RingBuffer(100);
        $this->lastSuccessAt = microtime(true);
    }

    public function run(): void
    {
        StartupBlock::write($this->config, $this->runId, [
            ['section' => 'mode', 'setting' => 'run_limit', 'value' => $this->runLimitDescription()],
            ['section' => 'mode', 'setting' => 'deterministic_smoke', 'value' => $this->config->commandsPerWorker === null],
        ]);

        $this->logger->info('starting fuzz run', [
            'seed' => $this->config->seed,
            'run_id' => $this->runId,
            'server' => "http://{$this->config->host}:{$this->config->port}",
            'client' => $this->config->client,
            'workers' => $this->config->workers,
            'run_limit' => $this->runLimitDescription(),
        ]);

        try {
            $this->startOwnedRedis();
            $this->logger->debug('connecting to Redis', [
                'host' => $this->config->redisHost,
                'port' => $this->config->redisPort,
                'db' => $this->config->redisDb,
            ]);
            $this->redis = new RedisClient(
                $this->config->redisHost,
                $this->config->redisPort,
                $this->config->redisDb,
                $this->config->requestTimeoutMs,
            );
            $this->redis->ping();
            $this->logger->debug('Redis ping succeeded');

            $this->http = new HttpClient($this->config->host, $this->config->port, $this->config->requestTimeoutMs);
            $this->server = new ServerProcess($this->config, $this->logger, runId: $this->runId);
            $this->server->start();
            $this->waitUntilReady();

            if ($this->config->commandsPerWorker === null) {
                $this->deterministicSmoke();
            } else {
                $this->logger->info('skipping deterministic smoke phase for command-count run');
            }

            $baseSuccessfulRequests = $this->stats['successful_requests'];
            $deadline = microtime(true) + $this->config->durationSeconds;

            while ($this->shouldContinueFuzzing($deadline, $baseSuccessfulRequests)) {
                $this->iteration();
            }

            $this->cleanupRedisKeys();
            $this->server->drain();
            $this->server->stop();
            $this->server->cleanupRuntimeDirectory();
            $this->logger->info('completed fuzz run', [
                'iterations' => $this->stats['iterations'],
                'requests' => $this->stats['total_requests'],
                'main_phase_successful_commands' => $this->stats['successful_requests'] - $baseSuccessfulRequests,
                'stale_observations' => $this->stats['stale_observations'],
            ]);
        } catch (Throwable $e) {
            $path = $this->failurePath ?? (isset($this->server) ? $this->maybeWriteReproducer('exception', ['message' => $e->getMessage()]) : null);
            $type = $this->failureType ?? ReproducerTypes::OTHER;

            if ($path !== null) {
                $this->logger->error('fuzz run failed', ['error' => $e->getMessage(), 'reproducer_type' => $type, 'reproducer' => $path]);
                throw new FuzzerException($e->getMessage() . "\nreproducer_type={$type}\nreproducer={$path}", previous: $e);
            }

            $this->logger->error('fuzz run failed without captured reproducer', ['error' => $e->getMessage(), 'reproducer_type' => $type]);
            throw new FuzzerException($e->getMessage() . "\nreproducer_type={$type}", previous: $e);
        } finally {
            if (isset($this->server)) {
                $this->server->stop();
            }
            $this->stopOwnedRedis();
        }
    }

    private function startOwnedRedis(): void
    {
        if ($this->config->redisServer === null) {
            return;
        }

        $this->redisServer = new RedisServerProcess($this->config, $this->logger, $this->runId);
        $this->redisServer->start();
    }

    private function stopOwnedRedis(): void
    {
        if ($this->redisServer instanceof RedisServerProcess) {
            $this->redisServer->stop();
            $this->redisServer = null;
        }
    }

    private function shouldContinueFuzzing(float $deadline, int $baseSuccessfulRequests): bool
    {
        if ($this->config->commandsPerWorker === null) {
            return microtime(true) < $deadline;
        }

        $target = $this->config->commandsPerWorker * $this->config->workers;

        return ($this->stats['successful_requests'] - $baseSuccessfulRequests) < $target;
    }

    private function runLimitDescription(): string
    {
        if ($this->config->commandsPerWorker !== null) {
            $target = $this->config->commandsPerWorker * $this->config->workers;

            return "commands_per_worker={$this->config->commandsPerWorker} target_successful_commands={$target}";
        }

        return "duration_seconds={$this->config->durationSeconds}";
    }

    private function waitUntilReady(): void
    {
        $deadline = microtime(true) + 10.0;
        $this->logger->debug('waiting for PHP CLI server to respond');

        while (microtime(true) < $deadline) {
            if (!$this->server->isRunning()) {
                $this->abort('PHP CLI server parent exited before becoming ready');
            }

            try {
                $this->discoverWorkers(requireExpectedCount: false);

                if ($this->observedPids !== []) {
                    $this->logger->info('PHP CLI server is ready', ['workers_seen' => count($this->observedPids)]);
                    return;
                }
            } catch (RequestException) {
            }

            usleep(50_000);
        }

        $this->abort('PHP CLI server did not become ready');
    }

    private function deterministicSmoke(): void
    {
        $this->logger->info('running deterministic smoke phase');
        $this->discoverWorkers(requireExpectedCount: true);
        $this->warmSome(max(8, $this->config->workers * $this->config->keysPerWorker * 3));

        $keys = array_keys($this->expected);
        $this->mutateKeys($keys);

        $pids = array_keys($this->observedPids);
        sort($pids);

        if ($pids !== []) {
            $this->killPid($pids[0], 15);
            usleep(100_000);
            $this->discoverWorkers(requireExpectedCount: false);
        }

        $this->verifyKeys($keys);
        $this->logger->info('deterministic smoke phase completed', ['keys' => count($keys)]);
    }

    private function iteration(): void
    {
        $this->stats['iterations']++;
        $this->logger->debug('starting iteration', ['iteration' => $this->stats['iterations']]);
        $this->ensureServerRunning();
        $this->discoverWorkers(requireExpectedCount: false);
        $this->warmSome(max(2, $this->config->workers * 2));

        $mutated = $this->pickMutationSubset();
        $this->mutateKeys($mutated);

        if ($this->rng->float() <= $this->config->killRate) {
            $this->killRandomWorkers();
            usleep(50_000);
            $this->discoverWorkers(requireExpectedCount: false);
        }

        $this->verifyKeys($mutated);
        $this->checkWatchdog();
        $this->logger->debug('completed iteration', [
            'iteration' => $this->stats['iterations'],
            'mutated_keys' => count($mutated),
        ]);
    }

    private function discoverWorkers(bool $requireExpectedCount): void
    {
        $target = $requireExpectedCount ? $this->config->workers : 1;
        $attempts = max(20, $this->config->workers * 20);
        $this->logger->debug('discovering workers', ['target' => $target, 'attempts' => $attempts]);

        for ($i = 0; $i < $attempts && count($this->observedPids) < $target; $i++) {
            $response = $this->tryRequest('/pid');

            if ($response === null) {
                usleep(20_000);
                continue;
            }

            $pid = $this->responsePid($response);
            $this->recordEvent(['type' => 'discover', 'pid' => $pid]);
            $this->observePid($pid);
        }

        if ($this->observedPids === []) {
            $this->abort('No PHP CLI server worker responded');
        }
    }

    private function observePid(int $pid): void
    {
        if (isset($this->observedPids[$pid])) {
            return;
        }

        $this->observedPids[$pid] = true;
        $this->stats['workers_discovered']++;
        $this->assignKeys($pid);

        $this->logger->notice('discovered worker', ['pid' => $pid, 'known_workers' => count($this->observedPids)]);
    }

    private function assignKeys(int $pid): void
    {
        if (isset($this->keysByPid[$pid])) {
            return;
        }

        $keys = [];

        for ($slot = 0; $slot < $this->config->keysPerWorker; $slot++) {
            $key = "relay-fuzz:{$this->runId}:{$pid}:{$slot}";
            $this->logger->debug('seeding Redis key for cache warmup', ['pid' => $pid, 'key' => $key, 'value' => 0]);
            $this->redis->set($key, '0');
            $this->expected[$key] = 0;
            $this->keyOwner[$key] = $pid;
            $keys[] = $key;
            $this->recordEvent(['type' => 'set', 'key' => $key, 'value' => '0']);
        }

        $this->keysByPid[$pid] = $keys;
    }

    private function warmSome(int $rounds): void
    {
        $this->logger->debug('warming keys through Relay', ['rounds' => $rounds, 'reads_per_round' => $this->config->warmupReads]);

        for ($i = 0; $i < $rounds; $i++) {
            $pids = array_keys($this->keysByPid);

            if ($pids === []) {
                $this->discoverWorkers(requireExpectedCount: false);
                $pids = array_keys($this->keysByPid);
            }

            $pid = $this->rng->pick($pids);
            $key = $this->rng->pick($this->keysByPid[$pid]);
            $this->logger->debug('attempting to cache key through Relay', [
                'round' => $i + 1,
                'pid_hint' => $pid,
                'key' => $key,
                'reads' => $this->config->warmupReads,
            ]);
            $response = $this->tryRequest('/warm?key=' . rawurlencode($key) . '&n=' . $this->config->warmupReads);

            if ($response === null) {
                continue;
            }

            $actualPid = $this->responsePid($response);
            $this->observePid($actualPid);
            $this->recordEvent([
                'type' => 'warm',
                'pid' => $actualPid,
                'key' => $key,
                'tracked' => $response['tracked'] ?? null,
                'value' => $response['value'] ?? null,
                'reads' => $this->config->warmupReads,
            ]);
        }
    }

    /**
     * @return list<string>
     */
    private function pickMutationSubset(): array
    {
        $keys = array_keys($this->expected);

        if ($keys === []) {
            return [];
        }

        $keys = $this->rng->shuffled($keys);
        $count = $this->rng->int(1, count($keys));

        return array_slice($keys, 0, $count);
    }

    /**
     * @param list<string> $keys
     */
    private function mutateKeys(array $keys): void
    {
        if ($keys !== []) {
            $this->logger->debug('mutating Redis keys directly', ['keys' => count($keys)]);
        }

        foreach ($keys as $key) {
            $this->logger->debug('incrementing Redis key', ['key' => $key, 'old_expected' => $this->expected[$key] ?? null]);
            $previous = $this->expected[$key] ?? null;
            $value = $this->redis->incr($key);
            $this->expected[$key] = $value;
            $event = [
                'type' => 'incr',
                'key' => $key,
                'previous_expected' => $previous === null ? null : (string) $previous,
                'expected_after' => (string) $value,
                'value' => (string) $value,
            ];
            $this->recordEvent($event);
            $this->lastMutations->push($event);
            $this->logger->debug('incremented Redis key', ['key' => $key, 'value' => $value]);
        }
    }

    private function killRandomWorkers(): void
    {
        $pids = array_keys($this->observedPids);
        $parentPid = $this->server->parentPid();

        if ($parentPid !== null) {
            $pids = array_values(array_filter($pids, static fn (int $pid): bool => $pid !== $parentPid));
        }

        if ($pids === []) {
            $this->logger->debug('no worker PIDs available to kill');
            return;
        }

        $pids = $this->rng->shuffled($pids);
        $count = $this->rng->int(1, min($this->config->maxKill, count($pids)));
        $this->logger->debug('selected workers for killing', ['count' => $count, 'candidates' => $pids]);

        foreach (array_slice($pids, 0, $count) as $pid) {
            $this->killPid($pid, $this->rng->weighted($this->config->signalWeights));
        }
    }

    private function killPid(int $pid, int $signal): void
    {
        if (!function_exists('posix_kill')) {
            $this->abort('posix_kill is required to kill worker processes');
        }

        $parentPid = $this->server->parentPid();

        if ($parentPid !== null && $pid === $parentPid) {
            $this->logger->debug('skipping kill for server parent', ['pid' => $pid]);
            return;
        }

        $signalName = self::signalName($signal);
        $this->logger->notice('killing worker process', ['pid' => $pid, 'signal' => $signalName]);
        $ok = @posix_kill($pid, $signal);
        $event = [
            'type' => 'kill',
            'pid' => $pid,
            'signal' => $signalName,
            'ok' => $ok,
        ];
        $this->recordEvent($event);
        $this->killedPids[$pid] = true;

        if ($ok) {
            unset($this->observedPids[$pid]);
            $this->stats['workers_killed']++;
            $this->logger->notice('sent worker signal', ['pid' => $pid, 'signal' => $signalName]);
        } else {
            $this->logger->warning('failed to signal worker', ['pid' => $pid, 'signal' => $signalName]);
        }
    }

    /**
     * @param list<string> $keys
     */
    private function verifyKeys(array $keys): void
    {
        if ($keys !== []) {
            $this->logger->debug('verifying keys through Relay', ['keys' => count($keys), 'retries' => $this->config->verifyRetries]);
        }

        foreach ($keys as $key) {
            $expected = (string) $this->expected[$key];
            $lastValueMismatch = null;
            $lastRequestFailure = null;

            for ($attempt = 1; $attempt <= $this->config->verifyRetries; $attempt++) {
                $this->logger->debug('doing verification read', [
                    'key' => $key,
                    'expected' => $expected,
                    'attempt' => $attempt,
                ]);
                $response = $this->tryRequest('/get?key=' . rawurlencode($key));

                if ($response === null) {
                    $lastRequestFailure = ['type' => 'request_failed', 'attempt' => $attempt];
                    $this->logger->debug('verification read failed; retrying', ['key' => $key, 'attempt' => $attempt]);
                    $this->delayBetweenVerifyAttempts();
                    continue;
                }

                $pid = $this->responsePid($response);
                $this->observePid($pid);
                $value = $response['value'] === null ? null : (string) $response['value'];

                $event = [
                    'type' => 'get',
                    'pid' => $pid,
                    'key' => $key,
                    'value' => $value,
                    'expected' => $expected,
                    'tracked' => $response['tracked'] ?? null,
                    'attempt' => $attempt,
                ];
                $this->recordEvent($event);

                if ($value === $expected) {
                    $this->logger->debug('verification read matched', [
                        'key' => $key,
                        'pid' => $pid,
                        'value' => $value,
                        'attempt' => $attempt,
                    ]);
                    $lastValueMismatch = null;
                    $lastRequestFailure = null;
                    break;
                }

                $lastValueMismatch = $event;
                $this->logger->warning('verification read mismatch', [
                    'key' => $key,
                    'pid' => $pid,
                    'value' => $value,
                    'expected' => $expected,
                    'attempt' => $attempt,
                ]);

                if ($value !== null && ctype_digit($value) && (int) $value < (int) $expected) {
                    $this->stats['stale_observations']++;
                    $this->lastStale->push($event);
                    $this->logger->warning('observed stale Relay value', [
                        'key' => $key,
                        'pid' => $pid,
                        'value' => $value,
                        'expected' => $expected,
                        'attempt' => $attempt,
                    ]);
                }

                $this->delayBetweenVerifyAttempts();
            }

            if ($lastValueMismatch !== null) {
                $this->stats['persistent_stale_failures']++;
                $redisValue = $this->redis->get($key);
                $context = [
                    'key' => $key,
                    'expected' => $expected,
                    'redis_value' => $redisValue,
                    'last_mismatch' => $lastValueMismatch,
                    'owner_pid' => $this->keyOwner[$key] ?? null,
                    'owner_pid_killed' => isset($this->killedPids[$this->keyOwner[$key] ?? 0]),
                ];

                if ($lastRequestFailure !== null) {
                    $context['last_request_failure'] = $lastRequestFailure;
                }

                $this->logger->error('persistent mismatch after verification retries', [
                    'key' => $key,
                    'expected' => $expected,
                    'redis_value' => $redisValue,
                ]);
                $this->abort('Persistent stale or mismatched value', $context);
            }

            if ($lastRequestFailure !== null) {
                $redisValue = $this->redis->get($key);
                $this->logger->error('verification request failed after retries', [
                    'key' => $key,
                    'expected' => $expected,
                    'redis_value' => $redisValue,
                ]);
                $this->abort('Verification request failed after retries', [
                    'key' => $key,
                    'expected' => $expected,
                    'redis_value' => $redisValue,
                    'last_request_failure' => $lastRequestFailure,
                    'owner_pid' => $this->keyOwner[$key] ?? null,
                    'owner_pid_killed' => isset($this->killedPids[$this->keyOwner[$key] ?? 0]),
                ]);
            }
        }
    }

    private function delayBetweenVerifyAttempts(): void
    {
        if ($this->config->verifyDelayUs > 0) {
            $this->logger->debug('waiting before another read', ['delay_us' => $this->config->verifyDelayUs]);
            usleep($this->config->verifyDelayUs);
        }
    }

    private function cleanupRedisKeys(): void
    {
        $keys = array_keys($this->expected);
        $this->logger->debug('cleaning Redis keys', ['keys' => count($keys)]);
        $this->redis->del($keys);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function tryRequest(string $path): ?array
    {
        $this->stats['total_requests']++;
        $startedAt = microtime(true);
        $this->logger->debug('sending request', ['path' => $path]);

        try {
            $response = $this->http->getJson($path);
            $this->stats['successful_requests']++;
            $this->lastSuccessAt = microtime(true);
            $elapsedMs = (int) round((microtime(true) - $startedAt) * 1000);
            $pid = is_int($response['pid'] ?? null) ? $response['pid'] : null;

            if ($pid !== null) {
                $this->workerCommandCounts[$pid] = ($this->workerCommandCounts[$pid] ?? 0) + 1;
            }

            $this->lastRequests->push([
                'path' => $path,
                'ok' => true,
                'elapsed_ms' => $elapsedMs,
                'pid' => $pid,
            ]);
            $this->logger->debug('request completed', [
                'path' => $path,
                'elapsed_ms' => $elapsedMs,
                'pid' => $pid,
            ]);

            return $response;
        } catch (RequestException $e) {
            $this->stats['failed_requests']++;

            if ($e->timedOut) {
                $this->stats['request_timeouts']++;
            }

            $elapsedMs = (int) round((microtime(true) - $startedAt) * 1000);
            $this->lastRequests->push([
                'path' => $path,
                'ok' => false,
                'timeout' => $e->timedOut,
                'error' => $e->getMessage(),
                'elapsed_ms' => $elapsedMs,
            ]);
            $this->logger->warning('request failed', [
                'path' => $path,
                'timeout' => $e->timedOut,
                'elapsed_ms' => $elapsedMs,
                'error' => $e->getMessage(),
            ]);
            $this->checkWatchdog();

            return null;
        }
    }

    /**
     * @param array<string, mixed> $response
     */
    private function responsePid(array $response): int
    {
        if (!isset($response['pid']) || !is_int($response['pid'])) {
            $this->abort('Response did not include an integer pid', ['response' => $response]);
        }

        return $response['pid'];
    }

    private function ensureServerRunning(): void
    {
        if (!$this->server->isRunning()) {
            $this->abort('PHP CLI server parent exited unexpectedly');
        }
    }

    private function checkWatchdog(): void
    {
        $elapsedMs = (int) round((microtime(true) - $this->lastSuccessAt) * 1000);

        if ($elapsedMs > $this->config->watchdogTimeoutMs) {
            $this->abort('No successful request completed before watchdog timeout', [
                'elapsed_ms' => $elapsedMs,
            ]);
        }
    }

    /**
     * @param array<string, mixed> $event
     */
    private function recordEvent(array $event): void
    {
        $event['time'] = sprintf('%.6f', microtime(true));
        $this->events[] = $event;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function abort(string $message, array $context = []): never
    {
        $this->logger->error('aborting fuzz run', ['reason' => $message, 'context' => $context]);
        $this->failurePath = $this->maybeWriteReproducer($message, $context);

        throw new FuzzerException($message);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function maybeWriteReproducer(string $reason, array $context): ?string
    {
        $type = ReproducerTypes::classify($reason, $context, $this->stats, $this->server, false);
        $this->failureType = $type;

        if (!ReproducerTypes::shouldCapture($this->config->captureTypes, $type)) {
            $this->logger->warning('skipping reproducer capture for filtered type', ['type' => $type, 'reason' => $reason]);
            return null;
        }

        return $this->writeReproducer($type, $reason, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function writeReproducer(string $type, string $reason, array $context): string
    {
        $this->server->drain();
        $bundlePath = ReproducerPaths::createBundleDirectory('random', $type);
        $path = $bundlePath . DIRECTORY_SEPARATOR . 'reproducer.json';
        $payload = [
            'reproducer_type' => $type,
            'reason' => $reason,
            'context' => $context,
            'seed' => $this->config->seed,
            'php' => $this->config->php,
            'client' => $this->config->client,
            'run_limit' => [
                'duration_seconds' => $this->config->durationSeconds,
                'commands_per_worker' => $this->config->commandsPerWorker,
                'target_successful_commands' => $this->config->commandsPerWorker === null
                    ? null
                    : $this->config->commandsPerWorker * $this->config->workers,
            ],
            'run_id' => $this->runId,
            'server' => [
                'transport' => $this->config->fpm ? 'fpm' : 'cli',
                'host' => $this->config->host,
                'port' => $this->config->port,
                'parent_pid' => $this->server->parentPid(),
                'command_line' => $this->server->commandLine(),
                'output' => $this->server->tails(),
                'runtime_dir' => $this->server->runtimeDirectory(),
                'startup_process_metadata' => $this->server->startupProcessMetadata(),
            ],
            'redis' => [
                'host' => $this->config->redisHost,
                'port' => $this->config->redisPort,
                'db' => $this->config->redisDb,
            ],
            'workers' => [
                'configured' => $this->config->workers,
                'observed_pids' => array_map('intval', array_keys($this->observedPids)),
                'killed_pids' => array_map('intval', array_keys($this->killedPids)),
            ],
            'relay_ini' => [
                'relay.max_endpoint_dbs' => $this->config->relayMaxEndpointDbs,
                'relay.max_db_writers' => $this->config->relayMaxDbWriters,
                'relay.cache' => 1,
                'relay.loglevel' => $this->config->captureRelayLogLevel,
                'relay.logfile' => $this->server->relayLogFile(),
            ],
            'stats' => $this->stats,
            'worker_command_counts' => $this->workerCommandCounts,
            'last_requests' => $this->lastRequests->all(),
            'last_mutations' => $this->lastMutations->all(),
            'last_stale_observations' => $this->lastStale->all(),
            'events' => $this->events,
        ];

        file_put_contents($path, json_encode($payload, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n");
        ServerProcessMetadataFiles::write($this->server, $bundlePath);
        $this->writeStaleSequenceLog($bundlePath, $type, $context);
        $this->server->copyRuntimeDirectory($bundlePath . DIRECTORY_SEPARATOR . 'server-runtime');
        $this->logger->error('wrote failure reproducer', ['path' => $bundlePath, 'reason' => $reason]);

        return $bundlePath;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function writeStaleSequenceLog(string $bundlePath, string $type, array $context): void
    {
        if ($type !== ReproducerTypes::STALE_KEY) {
            return;
        }

        $lines = StaleSequenceLog::lines($this->events, $context);

        if ($lines !== []) {
            file_put_contents($bundlePath . DIRECTORY_SEPARATOR . 'stale-sequence.log', implode("\n", $lines) . "\n");
        }
    }

    private static function pickFreePort(string $host): int
    {
        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_server("tcp://{$host}:0", $errno, $errstr);

        if ($socket === false) {
            throw new FuzzerException("Could not pick a free port on {$host}: {$errstr}");
        }

        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        if (!is_string($name) || !preg_match('/:(\d+)$/', $name, $matches)) {
            throw new FuzzerException('Could not parse free port');
        }

        return (int) $matches[1];
    }

    private static function signalName(int $signal): string
    {
        return match ($signal) {
            2 => 'SIGINT',
            9 => 'SIGKILL',
            15 => 'SIGTERM',
            default => 'SIG' . $signal,
        };
    }
}

final class SequentialFuzzer
{
    private Config $config;
    private Rng $rng;
    private RedisClient $redis;
    private HttpClient $http;
    private ServerProcess $server;
    private ?RedisServerProcess $redisServer = null;
    private LoggerInterface $logger;
    private string $runId;
    private ?string $rrTraceDir;

    /** @var array<int, true> */
    private array $workers = [];

    /** @var array<int, true> */
    private array $aliveWorkers = [];

    /** @var array<int, true> */
    private array $killedPids = [];

    /** @var array<int, list<string>> */
    private array $keysByPid = [];

    /** @var array<string, int> */
    private array $expected = [];

    /** @var array<string, int> */
    private array $keyOwner = [];

    /** @var list<array<string, mixed>> */
    private array $events = [];

    /** @var list<string> */
    private array $eventLines = [];

    /** @var list<array<string, mixed>> */
    private array $mutations = [];

    /** @var list<array<string, mixed>> */
    private array $staleObservations = [];

    /** @var array<string, mixed>|null */
    private ?array $failureContext = null;

    /** @var array<string, int> */
    private array $stats = [
        'requests' => 0,
        'failed_requests' => 0,
        'workers_discovered' => 0,
        'workers_killed' => 0,
        'stale_observations' => 0,
        'persistent_stale_failures' => 0,
    ];

    public function __construct(Config $config)
    {
        if ($config->port === 0) {
            $config = $config->withPort(self::pickFreePort($config->host));
        }
        if ($config->redisServer !== null && $config->redisPort === 0) {
            $config = $config->withRedisPort(self::pickFreePort($config->redisHost));
        }

        $this->config = $config;
        $this->logger = LogFactory::create($this->config);
        $this->rng = new Rng($this->config->seed);
        $this->runId = $this->config->runId ?? dechex($this->config->seed) . '-seq-' . bin2hex(random_bytes(3));
        $this->rrTraceDir = $this->prepareRrTraceDir();
    }

    public function run(): void
    {
        StartupBlock::write($this->config, $this->runId, [
            ['section' => 'mode', 'setting' => 'signal_strategy', 'value' => 'random'],
            ['section' => 'mode', 'setting' => 'rr_trace_dir_actual', 'value' => $this->rrTraceDir],
        ]);

        $this->logger->info('starting sequential fuzz run', [
            'seed' => $this->config->seed,
            'run_id' => $this->runId,
            'server' => "http://{$this->config->host}:{$this->config->port}",
            'client' => $this->config->client,
            'workers' => $this->config->workers,
            'delay_us' => $this->config->delayUs,
            'rr' => $this->config->rr,
            'rr_trace_dir' => $this->rrTraceDir,
        ]);

        try {
            $this->startOwnedRedis();
            $this->redis = new RedisClient(
                $this->config->redisHost,
                $this->config->redisPort,
                $this->config->redisDb,
                $this->config->requestTimeoutMs,
            );
            $this->redis->ping();

            $this->http = new HttpClient($this->config->host, $this->config->port, $this->config->requestTimeoutMs);
            $this->server = new ServerProcess($this->config, $this->logger, $this->rrTraceDir, $this->runId);
            $this->server->start();
            $this->waitUntilReady();
            $this->discoverInitialWorkers();
            $this->warmAllWorkers();
            $this->shutdownLoop();
            $this->finalWorkerPhase();
            $this->cleanupRedisKeys();
            $this->server->stop();
            $this->server->cleanupRuntimeDirectory();
            $this->cleanupTempTrace();

            $this->logger->info('completed sequential fuzz run', [
                'workers_killed' => $this->stats['workers_killed'],
                'stale_observations' => $this->stats['stale_observations'],
            ]);
        } catch (Throwable $e) {
            $serverStopTimedOut = isset($this->server) && !$this->server->stop();
            $context = $this->failureContext ?? [];
            $type = ReproducerTypes::classify($e->getMessage(), $context, $this->stats, $this->server ?? null, $serverStopTimedOut);

            if (!isset($this->server) || !ReproducerTypes::shouldCapture($this->config->captureTypes, $type)) {
                $this->logger->error('sequential fuzz run failed without captured reproducer', ['error' => $e->getMessage(), 'reproducer_type' => $type]);
                throw new FuzzerException($e->getMessage() . "\nreproducer_type={$type}", previous: $e);
            }

            $path = $this->writeBundle($type, $e->getMessage(), $context, $e);
            $this->logger->error('sequential fuzz run failed', ['error' => $e->getMessage(), 'reproducer_type' => $type, 'reproducer' => $path]);

            throw new FuzzerException($e->getMessage() . "\nreproducer_type={$type}\nreproducer={$path}", previous: $e);
        } finally {
            if (isset($this->server)) {
                $this->server->stop();
            }
            $this->stopOwnedRedis();
        }
    }

    private function startOwnedRedis(): void
    {
        if ($this->config->redisServer === null) {
            return;
        }

        $this->redisServer = new RedisServerProcess($this->config, $this->logger, $this->runId);
        $this->redisServer->start();
    }

    private function stopOwnedRedis(): void
    {
        if ($this->redisServer instanceof RedisServerProcess) {
            $this->redisServer->stop();
            $this->redisServer = null;
        }
    }

    private function waitUntilReady(): void
    {
        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline) {
            if (!$this->server->isRunning()) {
                $this->fail('PHP CLI server parent exited before becoming ready');
            }

            if ($this->tryRequest('/pid') !== null) {
                $this->logger->info('PHP CLI server is ready');
                return;
            }

            usleep(50_000);
        }

        $this->fail('PHP CLI server did not become ready');
    }

    private function discoverInitialWorkers(): void
    {
        $deadline = microtime(true) + 15.0;
        $attempt = 0;

        while (microtime(true) < $deadline && count($this->workers) < $this->config->workers) {
            $attempt++;
            $response = $this->tryRequest('/pid');

            if ($response === null) {
                usleep(20_000);
                continue;
            }

            $this->observePid($this->responsePid($response));

            if ($attempt % max(1, $this->config->workers * 10) === 0) {
                usleep(20_000);
            }
        }

        if (count($this->workers) < $this->config->workers) {
            $this->fail('Could not discover all configured workers', [
                'expected' => $this->config->workers,
                'observed' => array_keys($this->workers),
            ]);
        }

        $this->aliveWorkers = $this->workers;
    }

    private function observePid(int $pid): void
    {
        $parentPid = $this->server->parentPid();

        if ($parentPid !== null && $pid === $parentPid) {
            return;
        }

        if (isset($this->workers[$pid])) {
            return;
        }

        $this->workers[$pid] = true;
        $this->stats['workers_discovered']++;
        $this->assignKeys($pid);
        $this->recordEvent('discover', ['pid' => $pid]);
        $this->logLine('DISCOVER', ['pid' => $pid, 'known' => count($this->workers)]);
    }

    private function assignKeys(int $pid): void
    {
        $keys = [];

        for ($slot = 0; $slot < $this->config->keysPerWorker; $slot++) {
            $key = "relay-fuzz:{$this->runId}:{$pid}:{$slot}";
            $this->redis->set($key, '0');
            $this->expected[$key] = 0;
            $this->keyOwner[$key] = $pid;
            $keys[] = $key;
            $this->recordEvent('set', ['pid' => $pid, 'key' => $key, 'value' => '0']);
        }

        $this->keysByPid[$pid] = $keys;
    }

    private function warmAllWorkers(): void
    {
        foreach (array_keys($this->workers) as $pid) {
            foreach ($this->keysByPid[$pid] as $key) {
                $this->warmKeyOnWorker($pid, $key);
                $this->sequentialDelay('warm');
            }
        }

        $this->logLine('OK', ['phase' => 'warmup', 'workers' => count($this->workers)]);
    }

    private function warmKeyOnWorker(int $targetPid, string $key): void
    {
        $attempts = 0;
        $deadline = microtime(true) + max(5.0, $this->config->watchdogTimeoutMs / 1000);
        $responsePidCounts = [];
        $nullResponses = 0;

        while (microtime(true) < $deadline) {
            $attempts++;
            $response = $this->tryRequest('/warm?key=' . rawurlencode($key) . '&n=' . $this->config->warmupReads);

            if ($response === null) {
                $nullResponses++;
                usleep(10_000);
                continue;
            }

            $pid = $this->responsePid($response);
            $responsePidCounts[$pid] = ($responsePidCounts[$pid] ?? 0) + 1;
            $this->observePid($pid);
            $tracked = $response['tracked'] ?? null;
            $value = $response['value'] === null ? null : (string) $response['value'];
            $this->recordEvent('warm', [
                'pid' => $pid,
                'target_pid' => $targetPid,
                'key' => $key,
                'tracked' => $tracked,
                'value' => $value,
                'reads' => $this->config->warmupReads,
                'attempt' => $attempts,
            ]);

            if ($pid === $targetPid) {
                $this->logLine('WARM', [
                    'pid' => $pid,
                    'key' => $key,
                    'tracked' => $tracked === true ? 'yes' : 'no',
                ]);
                return;
            }

            if ($attempts % 100 === 0) {
                $this->logger->debug('warm request has not reached target worker', [
                    'target_pid' => $targetPid,
                    'key' => $key,
                    'attempts' => $attempts,
                    'response_pid_counts' => $responsePidCounts,
                    'null_responses' => $nullResponses,
                ]);
            }

            usleep(10_000);
        }

        ksort($responsePidCounts);
        $this->fail('Could not route warmup request to target worker', [
            'pid' => $targetPid,
            'key' => $key,
            'attempts' => $attempts,
            'null_responses' => $nullResponses,
            'response_pid_counts' => $responsePidCounts,
            'parent_pid' => $this->server->parentPid(),
            'observed_pids' => array_map('intval', array_keys($this->workers)),
            'alive_pids' => array_map('intval', array_keys($this->aliveWorkers)),
            'process_states' => $this->processStates([$targetPid, ...array_keys($this->workers)]),
        ]);
    }

    private function shutdownLoop(): void
    {
        while (count($this->aliveWorkers) > 1) {
            $pid = $this->pickAliveWorker();
            $signal = $this->rng->weighted($this->config->signalWeights);
            $signalName = self::signalName($signal);

            $this->logLine('KILL', ['pid' => $pid, 'signal' => $signalName]);
            $this->killPid($pid, $signal);
            $this->waitForWorkerDeath($pid, $signal !== 9);
            unset($this->aliveWorkers[$pid]);
            $this->sequentialDelay('worker death');

            $keys = $this->keysByPid[$pid] ?? [];
            $this->mutateKeys($keys);
            $this->sequentialDelay('mutation');
            $this->verifyKeys($keys, $this->aliveWorkers);
            $this->sequentialDelay('verification');

            $this->logLine('OK', ['pid' => $pid, 'remaining_workers' => count($this->aliveWorkers)]);
        }
    }

    private function finalWorkerPhase(): void
    {
        $alive = array_keys($this->aliveWorkers);
        $pid = $alive[0] ?? null;

        if ($pid === null) {
            $this->fail('No final worker remained for final phase');
        }

        $keys = array_keys($this->expected);
        $this->logLine('FINAL', ['pid' => $pid, 'keys' => count($keys)]);
        $this->mutateKeys($keys);
        $this->sequentialDelay('final mutation');
        $this->verifyKeys($keys, $this->aliveWorkers);
        $this->recordFinalCacheState($keys);

        $signal = $this->rng->weighted($this->config->signalWeights);
        $signalName = self::signalName($signal);
        $this->logLine('KILL', ['pid' => $pid, 'signal' => $signalName, 'final' => true]);
        $this->killPid($pid, $signal);
        $this->waitForWorkerDeath($pid, $signal !== 9);
        unset($this->aliveWorkers[$pid]);
        $this->logLine('OK', ['phase' => 'final-worker']);
    }

    private function pickAliveWorker(): int
    {
        $pids = array_keys($this->aliveWorkers);
        sort($pids);

        return $this->rng->pick($pids);
    }

    private function killPid(int $pid, int $signal): void
    {
        if (!function_exists('posix_kill')) {
            $this->fail('posix_kill is required for sequential mode');
        }

        $ok = @posix_kill($pid, $signal);
        $signalName = self::signalName($signal);
        $this->recordEvent('kill', [
            'pid' => $pid,
            'signal' => $signalName,
            'ok' => $ok,
        ]);
        $alreadyKilled = isset($this->killedPids[$pid]);
        $this->killedPids[$pid] = true;

        if (!$ok) {
            $this->fail('Failed to signal worker', ['pid' => $pid, 'signal' => $signalName]);
        }

        if (!$alreadyKilled) {
            $this->stats['workers_killed']++;
        }
    }

    private function waitForWorkerDeath(int $pid, bool $allowEscalation): void
    {
        if ($this->waitForWorkerExit($pid)) {
            return;
        }

        if ($allowEscalation) {
            $this->logLine('KILL', ['pid' => $pid, 'signal' => 'SIGKILL', 'escalated' => true], 'warning');
            $this->killPid($pid, 9);

            if ($this->waitForWorkerExit($pid)) {
                return;
            }
        }

        $this->fail('Worker death was not observed before timeout', ['pid' => $pid]);
    }

    private function waitForWorkerExit(int $pid): bool
    {
        $deadline = microtime(true) + max(1.0, $this->config->watchdogTimeoutMs / 1000);

        while (microtime(true) < $deadline) {
            if (!$this->processExists($pid)) {
                $this->recordEvent('death_observed', ['pid' => $pid]);
                $this->logLine('DEAD', ['pid' => $pid]);
                return true;
            }

            $response = $this->tryRequest('/pid');

            if ($response !== null && $this->responsePid($response) === $pid) {
                usleep(20_000);
                continue;
            }

            usleep(20_000);
        }

        return false;
    }

    /**
     * @param list<string> $keys
     */
    private function mutateKeys(array $keys): void
    {
        foreach ($keys as $key) {
            $previous = $this->expected[$key] ?? null;
            $value = $this->redis->incr($key);
            $this->expected[$key] = $value;
            $event = [
                'op' => 'INCR',
                'key' => $key,
                'previous_expected' => $previous,
                'expected' => $value,
                'expected_after' => $value,
                'owner_pid' => $this->keyOwner[$key] ?? null,
            ];
            $this->mutations[] = $event;
            $this->recordEvent('incr', $event);
            $this->logLine('INVALIDATE', $event);
        }
    }

    /**
     * @param list<string> $keys
     * @param array<int, true> $survivors
     */
    private function verifyKeys(array $keys, array $survivors): void
    {
        foreach ($keys as $key) {
            $this->verifyKey($key, $survivors);
        }
    }

    /**
     * @param array<int, true> $survivors
     */
    private function verifyKey(string $key, array $survivors): void
    {
        $expected = (string) $this->expected[$key];
        $survivorCount = max(1, count($survivors));
        $maxAttempts = max($this->config->verifyRetries, $this->config->verifyRetries * $survivorCount);
        $lastValueMismatch = null;
        $lastRequestFailure = null;
        $seen = [];

        for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
            $response = $this->tryRequest('/get?key=' . rawurlencode($key));

            if ($response === null) {
                $lastRequestFailure = ['type' => 'request_failed', 'attempt' => $attempt];
                $this->verifyDelay();
                continue;
            }

            $pid = $this->responsePid($response);
            $value = $response['value'] === null ? null : (string) $response['value'];
            $tracked = $response['tracked'] ?? null;
            $event = [
                'pid' => $pid,
                'key' => $key,
                'value' => $value,
                'expected' => $expected,
                'tracked' => $tracked,
                'attempt' => $attempt,
            ];
            $this->recordEvent('get', $event);
            $this->logLine('VERIFY', $event);

            if (isset($this->killedPids[$pid])) {
                $this->fail('Killed worker served a request after death was observed', $event);
            }

            if (!isset($survivors[$pid])) {
                $this->observePid($pid);
            }

            if ($value === $expected) {
                if (isset($survivors[$pid])) {
                    $seen[$pid] = true;
                }

                $lastValueMismatch = null;
                $lastRequestFailure = null;

                if (count($seen) >= count($survivors)) {
                    return;
                }

                continue;
            }

            $lastValueMismatch = $event;

            if ($value !== null && ctype_digit($value) && (int) $value < (int) $expected) {
                $this->stats['stale_observations']++;
                $this->staleObservations[] = $event;
                $this->logLine('STALE', $event, 'warning');
            }

            $this->verifyDelay();
        }

        if ($lastValueMismatch !== null) {
            $this->stats['persistent_stale_failures']++;
            $redisValue = $this->redis->get($key);
            $context = [
                'key' => $key,
                'expected' => $expected,
                'redis_value' => $redisValue,
                'last_mismatch' => $lastValueMismatch,
                'owner_pid' => $this->keyOwner[$key] ?? null,
                'owner_pid_killed' => isset($this->killedPids[$this->keyOwner[$key] ?? 0]),
                'survivors' => array_keys($survivors),
            ];

            if ($lastRequestFailure !== null) {
                $context['last_request_failure'] = $lastRequestFailure;
            }

            $this->fail('Persistent stale or mismatched value in sequential mode', $context);
        }

        if ($lastRequestFailure !== null) {
            $redisValue = $this->redis->get($key);
            $this->fail('Verification request failed after retries in sequential mode', [
                'key' => $key,
                'expected' => $expected,
                'redis_value' => $redisValue,
                'last_request_failure' => $lastRequestFailure,
                'owner_pid' => $this->keyOwner[$key] ?? null,
                'owner_pid_killed' => isset($this->killedPids[$this->keyOwner[$key] ?? 0]),
                'survivors' => array_keys($survivors),
            ]);
        }
    }

    /**
     * @param list<string> $keys
     */
    private function recordFinalCacheState(array $keys): void
    {
        foreach ($keys as $key) {
            $response = $this->tryRequest('/tracked?key=' . rawurlencode($key));

            if ($response === null) {
                continue;
            }

            $event = [
                'pid' => $this->responsePid($response),
                'key' => $key,
                'tracked' => $response['tracked'] ?? null,
            ];
            $this->recordEvent('final_cache_state', $event);
            $this->logLine('FINAL', $event);
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function tryRequest(string $path): ?array
    {
        $this->stats['requests']++;

        try {
            return $this->http->getJson($path);
        } catch (RequestException $e) {
            $this->stats['failed_requests']++;
            $this->logger->debug('request failed', [
                'path' => $path,
                'timeout' => $e->timedOut,
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * @param array<string, mixed> $response
     */
    private function responsePid(array $response): int
    {
        if (!isset($response['pid']) || !is_int($response['pid'])) {
            $this->fail('Response did not include an integer pid', ['response' => $response]);
        }

        return $response['pid'];
    }

    private function sequentialDelay(string $reason): void
    {
        if ($this->config->delayUs <= 0) {
            return;
        }

        $this->logger->debug('sequential delay', ['reason' => $reason, 'delay_us' => $this->config->delayUs]);
        usleep($this->config->delayUs);
    }

    private function verifyDelay(): void
    {
        if ($this->config->verifyDelayUs <= 0) {
            return;
        }

        $this->logger->debug('verification delay', ['delay_us' => $this->config->verifyDelayUs]);
        usleep($this->config->verifyDelayUs);
    }

    private function cleanupRedisKeys(): void
    {
        $this->redis->del(array_keys($this->expected));
    }

    private function processExists(int $pid): bool
    {
        if (!function_exists('posix_kill') || !@posix_kill($pid, 0)) {
            return false;
        }

        $stat = @file_get_contents("/proc/{$pid}/stat");

        if (is_string($stat) && preg_match('/^\d+\s+\(.+\)\s+([A-Z])\s/', $stat, $matches)) {
            return $matches[1] !== 'Z';
        }

        return true;
    }

    /**
     * @param list<int> $pids
     * @return array<int, array<string, mixed>>
     */
    private function processStates(array $pids): array
    {
        $states = [];

        $parentPid = $this->server->parentPid();
        if ($parentPid !== null) {
            $pids[] = $parentPid;
        }

        foreach (array_unique($pids) as $pid) {
            $states[(int) $pid] = $this->processState((int) $pid);
        }

        ksort($states);

        return $states;
    }

    /**
     * @return array<string, mixed>
     */
    private function processState(int $pid): array
    {
        $state = [
            'exists' => $this->processExists($pid),
        ];

        $stat = @file_get_contents("/proc/{$pid}/stat");
        if (is_string($stat) && preg_match('/^(\d+)\s+\((.*)\)\s+([A-Z])\s+(\d+)/', $stat, $matches)) {
            $state['comm'] = $matches[2];
            $state['state'] = $matches[3];
            $state['ppid'] = (int) $matches[4];
        }

        $wchan = @file_get_contents("/proc/{$pid}/wchan");
        if (is_string($wchan)) {
            $state['wchan'] = trim($wchan);
        }

        return $state;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function fail(string $message, array $context = []): never
    {
        $this->failureContext = $context;
        $this->recordEvent('failure', ['message' => $message, 'context' => $context]);
        $this->logger->error('aborting sequential fuzz run', ['reason' => $message, 'context' => $context]);

        throw new FuzzerException($message);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function recordEvent(string $type, array $context): void
    {
        $this->events[] = ['time' => sprintf('%.6f', microtime(true)), 'type' => $type] + $context;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logLine(string $tag, array $context, string $level = 'info'): void
    {
        $line = '[' . $tag . ']';

        foreach ($context as $key => $value) {
            if (is_bool($value)) {
                $value = $value ? 'true' : 'false';
            } elseif ($value === null) {
                $value = 'null';
            } elseif (!is_scalar($value)) {
                $value = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            }

            $line .= ' ' . $key . '=' . (string) $value;
        }

        $this->eventLines[] = sprintf('[%.6f] %s', microtime(true), $line);

        if ($level === 'warning') {
            $this->logger->warning($line);
            return;
        }

        $this->logger->info($line);
    }

    private function prepareRrTraceDir(): ?string
    {
        if (!$this->config->rr) {
            return null;
        }

        $root = $this->config->rrTraceDir ?? sys_get_temp_dir();
        $path = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'relay-cache-fuzzer-rr-' . $this->runId;

        if (!is_dir($path) && !mkdir($path, 0777, true)) {
            throw new FuzzerException("Could not create rr trace directory {$path}");
        }

        return $path;
    }

    private function cleanupTempTrace(): void
    {
        if (!$this->config->rr || $this->config->keepTemp || $this->config->rrTraceDir !== null || $this->rrTraceDir === null) {
            return;
        }

        $this->removeTree($this->rrTraceDir);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function writeBundle(string $type, string $reason, array $context, Throwable $throwable): string
    {
        $this->server->drain();

        $path = ReproducerPaths::createBundleDirectory('sequential', $type);

        $commandLine = $this->server->commandLine();
        $output = $this->server->outputText();
        $startup = [
            'seed' => $this->config->seed,
            'timestamp' => date(DATE_ATOM),
            'argv' => array_values(array_map('strval', $_SERVER['argv'] ?? [])),
            'php' => $this->config->php,
            'client' => $this->config->client,
            'server_transport' => $this->config->fpm ? 'fpm' : 'cli',
            'command_line' => $commandLine,
            'runtime_dir' => $this->server->runtimeDirectory(),
            'startup_process_metadata' => $this->server->startupProcessMetadata(),
            'relay_ini' => [
                'relay.max_endpoint_dbs' => $this->config->relayMaxEndpointDbs,
                'relay.max_db_writers' => $this->config->relayMaxDbWriters,
                'relay.cache' => 1,
                'relay.loglevel' => $this->config->captureRelayLogLevel,
                'relay.logfile' => $this->server->relayLogFile(),
            ],
            'workers' => $this->config->workers,
            'redis' => [
                'host' => $this->config->redisHost,
                'port' => $this->config->redisPort,
                'db' => $this->config->redisDb,
            ],
            'signal_strategy' => 'random',
            'signal_weights' => $this->config->signalWeights,
            'delay_us' => $this->config->delayUs,
            'verify_retries' => $this->config->verifyRetries,
            'verify_delay_us' => $this->config->verifyDelayUs,
            'rr' => $this->config->rr,
            'rr_trace_dir' => $this->rrTraceDir,
        ];
        $reproducer = [
            'reproducer_type' => $type,
            'reason' => $reason,
            'exception' => $throwable::class,
            'message' => $throwable->getMessage(),
            'context' => $context,
            'run_id' => $this->runId,
            'stats' => $this->stats,
            'workers' => [
                'observed_pids' => array_map('intval', array_keys($this->workers)),
                'alive_pids' => array_map('intval', array_keys($this->aliveWorkers)),
                'killed_pids' => array_map('intval', array_keys($this->killedPids)),
                'keys_by_pid' => $this->keysByPid,
            ],
            'expected' => $this->expected,
            'mutations' => $this->mutations,
            'stale_observations' => $this->staleObservations,
            'events' => $this->events,
        ];

        file_put_contents($path . '/startup.json', json_encode($startup, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
        file_put_contents($path . '/reproducer.json', json_encode($reproducer, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
        file_put_contents($path . '/events.log', implode("\n", $this->eventLines) . ($this->eventLines === [] ? '' : "\n"));
        $this->writeStaleSequenceLog($path, $type, $context);
        file_put_contents($path . '/server.stdout', $output['stdout']);
        file_put_contents($path . '/server.stderr', $output['stderr']);
        ServerProcessMetadataFiles::write($this->server, $path);
        $this->server->copyRuntimeDirectory($path . '/server-runtime');

        if ($this->config->rr && $this->rrTraceDir !== null) {
            $this->preserveRrTrace($path . '/rr');
        }

        return $path;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function writeStaleSequenceLog(string $path, string $type, array $context): void
    {
        if ($type !== ReproducerTypes::STALE_KEY) {
            return;
        }

        $lines = StaleSequenceLog::lines($this->events, $context);

        if ($lines !== []) {
            file_put_contents($path . '/stale-sequence.log', implode("\n", $lines) . "\n");
        }
    }

    private function preserveRrTrace(string $destination): void
    {
        if ($this->rrTraceDir === null || !is_dir($this->rrTraceDir)) {
            file_put_contents(dirname($destination) . '/rr-missing.txt', "rr trace directory was not found\n");
            return;
        }

        if (!$this->waitForRrTraceFinalized($this->rrTraceDir)) {
            file_put_contents(dirname($destination) . '/rr-incomplete.txt', "rr trace still had an incomplete file and was not copied\n");
            return;
        }

        $this->copyTree($this->rrTraceDir, $destination);
    }

    private function waitForRrTraceFinalized(string $traceDir): bool
    {
        $deadline = microtime(true) + 15.0;

        while (microtime(true) < $deadline) {
            if (!$this->treeContainsBasename($traceDir, 'incomplete')) {
                return true;
            }

            usleep(100_000);
        }

        return false;
    }

    private function treeContainsBasename(string $path, string $basename): bool
    {
        if (!is_dir($path)) {
            return false;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
        );

        foreach ($iterator as $item) {
            if ($item->getBasename() === $basename) {
                return true;
            }
        }

        return false;
    }

    private function copyTree(string $source, string $destination): void
    {
        if (!mkdir($destination, 0777, true) && !is_dir($destination)) {
            throw new FuzzerException("Could not create rr bundle directory {$destination}");
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
        );

        foreach ($iterator as $item) {
            $target = $destination . DIRECTORY_SEPARATOR . $iterator->getSubPathName();

            if ($item->isDir()) {
                if (!is_dir($target) && !mkdir($target, 0777, true)) {
                    throw new FuzzerException("Could not create directory {$target}");
                }

                continue;
            }

            if (!copy($item->getPathname(), $target)) {
                throw new FuzzerException("Could not copy rr trace file {$item->getPathname()}");
            }
        }
    }

    private function removeTree(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                rmdir($item->getPathname());
                continue;
            }

            unlink($item->getPathname());
        }

        rmdir($path);
    }

    private static function pickFreePort(string $host): int
    {
        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_server("tcp://{$host}:0", $errno, $errstr);

        if ($socket === false) {
            throw new FuzzerException("Could not pick a free port on {$host}: {$errstr}");
        }

        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        if (!is_string($name) || !preg_match('/:(\d+)$/', $name, $matches)) {
            throw new FuzzerException('Could not parse free port');
        }

        return (int) $matches[1];
    }

    private static function signalName(int $signal): string
    {
        return match ($signal) {
            2 => 'SIGINT',
            9 => 'SIGKILL',
            15 => 'SIGTERM',
            default => 'SIG' . $signal,
        };
    }
}

final class SimpleSequentialFuzzer
{
    private Config $config;
    private Rng $rng;
    private RedisClient $redis;
    private HttpClient $http;
    private ServerProcess $server;
    private ?RedisServerProcess $redisServer = null;
    private LoggerInterface $logger;
    private string $runId;
    private ?string $rrTraceDir;

    /** @var list<string> */
    private array $keys = [];

    /** @var array<string, int> */
    private array $expected = [];

    /** @var array<int, true> */
    private array $workers = [];

    /** @var array<int, true> */
    private array $aliveWorkers = [];

    /** @var array<int, true> */
    private array $killedPids = [];

    /** @var list<array<string, mixed>> */
    private array $events = [];

    /** @var list<string> */
    private array $eventLines = [];

    /** @var list<array<string, mixed>> */
    private array $mutations = [];

    /** @var list<array<string, mixed>> */
    private array $staleObservations = [];

    /** @var array<string, mixed>|null */
    private ?array $lastMutation = null;

    /** @var array<string, mixed>|null */
    private ?array $lastKilledWorker = null;

    /** @var array<string, mixed>|null */
    private ?array $failureContext = null;

    /** @var array<string, int> */
    private array $stats = [
        'requests' => 0,
        'failed_requests' => 0,
        'workers_discovered' => 0,
        'workers_killed' => 0,
        'mutations' => 0,
        'flushdb_mutations' => 0,
        'flushall_mutations' => 0,
        'verify_scans' => 0,
        'stale_observations' => 0,
        'persistent_stale_failures' => 0,
    ];

    public function __construct(Config $config)
    {
        if ($config->port === 0) {
            $config = $config->withPort(self::pickFreePort($config->host));
        }
        if ($config->redisServer !== null && $config->redisPort === 0) {
            $config = $config->withRedisPort(self::pickFreePort($config->redisHost));
        }

        $this->config = $config;
        $this->logger = LogFactory::create($this->config);
        $this->rng = new Rng($this->config->seed);
        $this->runId = $this->config->runId ?? dechex($this->config->seed) . '-simple-seq-' . bin2hex(random_bytes(3));
        $this->rrTraceDir = $this->prepareRrTraceDir();
    }

    public function run(): void
    {
        StartupBlock::write($this->config, $this->runId, [
            ['section' => 'mode', 'setting' => 'keyspace', 'value' => 'shared'],
            ['section' => 'mode', 'setting' => 'mutations_per_worker_death', 'value' => $this->config->mutations],
            ['section' => 'mode', 'setting' => 'rr_trace_dir_actual', 'value' => $this->rrTraceDir],
        ]);

        $this->logger->info('starting simple sequential fuzz run', [
            'seed' => $this->config->seed,
            'run_id' => $this->runId,
            'server' => "http://{$this->config->host}:{$this->config->port}",
            'client' => $this->config->client,
            'workers' => $this->config->workers,
            'keys' => $this->config->keys,
            'mutations' => $this->config->mutations,
            'signals' => array_map(self::signalName(...), $this->config->signals),
            'delay_us' => $this->config->delayUs,
            'rr' => $this->config->rr,
            'rr_trace_dir' => $this->rrTraceDir,
        ]);
        $this->logLine('START', [
            'workers' => $this->config->workers,
            'keys' => $this->config->keys,
            'mutations' => $this->config->mutations,
        ]);

        try {
            $this->startOwnedRedis();
            $this->redis = new RedisClient(
                $this->config->redisHost,
                $this->config->redisPort,
                $this->config->redisDb,
                $this->config->requestTimeoutMs,
            );
            $this->redis->ping();
            $this->initializeKeyspace();

            $this->http = new HttpClient($this->config->host, $this->config->port, $this->config->requestTimeoutMs);
            $this->server = new ServerProcess($this->config, $this->logger, $this->rrTraceDir, $this->runId);
            $this->server->start();
            $this->waitUntilReady();
            $this->discoverInitialWorkers();
            $this->warmKeyspace();
            $this->shutdownLoop();
            $this->cleanupRedisKeys();
            $this->server->stop();
            $this->server->cleanupRuntimeDirectory();
            $this->cleanupTempTrace();

            $this->logger->info('completed simple sequential fuzz run', [
                'workers_killed' => $this->stats['workers_killed'],
                'verify_scans' => $this->stats['verify_scans'],
                'stale_observations' => $this->stats['stale_observations'],
            ]);
        } catch (Throwable $e) {
            $serverStopTimedOut = isset($this->server) && !$this->server->stop();
            $context = $this->failureContext ?? [];
            $type = ReproducerTypes::classify($e->getMessage(), $context, $this->stats, $this->server ?? null, $serverStopTimedOut);

            if (!isset($this->server) || !ReproducerTypes::shouldCapture($this->config->captureTypes, $type)) {
                $this->logger->error('simple sequential fuzz run failed without captured reproducer', ['error' => $e->getMessage(), 'reproducer_type' => $type]);
                throw new FuzzerException($e->getMessage() . "\nreproducer_type={$type}", previous: $e);
            }

            $path = $this->writeBundle($type, $e->getMessage(), $context, $e);
            $this->logger->error('simple sequential fuzz run failed', ['error' => $e->getMessage(), 'reproducer_type' => $type, 'reproducer' => $path]);

            throw new FuzzerException($e->getMessage() . "\nreproducer_type={$type}\nreproducer={$path}", previous: $e);
        } finally {
            if (isset($this->server)) {
                $this->server->stop();
            }
            $this->stopOwnedRedis();
        }
    }

    private function startOwnedRedis(): void
    {
        if ($this->config->redisServer === null) {
            return;
        }

        $this->redisServer = new RedisServerProcess($this->config, $this->logger, $this->runId);
        $this->redisServer->start();
    }

    private function stopOwnedRedis(): void
    {
        if ($this->redisServer instanceof RedisServerProcess) {
            $this->redisServer->stop();
            $this->redisServer = null;
        }
    }

    private function initializeKeyspace(): void
    {
        if ($this->config->keyspaceIsolated) {
            $this->recordEvent('isolate_keyspace', ['phase' => 'init']);
        } else {
            $this->redis->flushDb();
            $this->recordEvent('flushdb', ['phase' => 'init']);
        }

        $this->keys = [];
        $this->expected = [];

        for ($i = 0; $i < $this->config->keys; $i++) {
            $key = "relay-fuzz:{$this->runId}:key:{$i}";
            $this->keys[] = $key;
            $this->redis->set($key, '1');
            $this->expected[$key] = 1;
            $this->recordEvent('set', ['phase' => 'init', 'key' => $key, 'value' => '1']);
        }

        $this->logLine('INIT', [
            'flushdb' => !$this->config->keyspaceIsolated,
            'keyspace_isolated' => $this->config->keyspaceIsolated,
            'keys' => count($this->keys),
            'value' => 1,
        ]);
    }

    private function rebuildKeyspaceAfterFlush(): void
    {
        foreach ($this->keys as $key) {
            $previous = $this->expected[$key] ?? null;
            $this->redis->set($key, '1');
            $this->expected[$key] = 1;
            $this->recordEvent('set', [
                'phase' => 'rebuild',
                'key' => $key,
                'previous_expected' => $previous,
                'expected_after' => 1,
                'value' => '1',
            ]);
        }

        $this->logLine('MUTATE', ['op' => 'REBUILD', 'keys' => count($this->keys), 'value' => 1]);
    }

    private function waitUntilReady(): void
    {
        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline) {
            if (!$this->server->isRunning()) {
                $this->fail('PHP CLI server parent exited before becoming ready');
            }

            if ($this->tryRequest('/pid') !== null) {
                $this->logger->info('PHP CLI server is ready');
                return;
            }

            usleep(50_000);
        }

        $this->fail('PHP CLI server did not become ready');
    }

    private function discoverInitialWorkers(): void
    {
        $deadline = microtime(true) + 15.0;

        while (microtime(true) < $deadline && count($this->workers) < $this->config->workers) {
            $response = $this->tryRequest('/pid');

            if ($response === null) {
                usleep(20_000);
                continue;
            }

            $this->observePid($this->responsePid($response), alive: true);
            usleep(10_000);
        }

        if (count($this->workers) < $this->config->workers) {
            $this->fail('Could not discover all configured workers', [
                'expected' => $this->config->workers,
                'observed' => array_keys($this->workers),
            ]);
        }
    }

    private function observePid(int $pid, bool $alive): void
    {
        $parentPid = $this->server->parentPid();

        if ($parentPid !== null && $pid === $parentPid) {
            return;
        }

        if (!isset($this->workers[$pid])) {
            $this->workers[$pid] = true;
            $this->stats['workers_discovered']++;
            $this->recordEvent('discover', ['pid' => $pid]);
            $this->logLine('DISCOVER', ['pid' => $pid, 'known' => count($this->workers)]);
        }

        if ($alive && !isset($this->killedPids[$pid])) {
            $this->aliveWorkers[$pid] = true;
        }
    }

    private function warmKeyspace(): void
    {
        foreach ($this->keys as $key) {
            $response = $this->tryRequest('/warm?key=' . rawurlencode($key) . '&n=' . $this->config->warmupReads);

            if ($response === null) {
                continue;
            }

            $pid = $this->responsePid($response);
            $this->observePid($pid, alive: true);
            $this->recordEvent('warm', [
                'pid' => $pid,
                'key' => $key,
                'value' => $response['value'] === null ? null : (string) $response['value'],
                'tracked' => $response['tracked'] ?? null,
                'reads' => $this->config->warmupReads,
            ]);
        }

        $this->logLine('WARMUP', ['consumed' => 'keyspace', 'keys' => count($this->keys)]);
    }

    private function shutdownLoop(): void
    {
        while ($this->aliveWorkers !== []) {
            $pid = $this->pickAliveWorker();
            $signal = $this->rng->pick($this->config->signals);
            $signalName = self::signalName($signal);

            $this->lastKilledWorker = ['pid' => $pid, 'signal' => $signalName];
            $this->logLine('KILL', ['pid' => $pid, 'signal' => $signalName]);
            $this->killPid($pid, $signal);
            $this->waitForWorkerDeath($pid, $signal !== 9);
            unset($this->aliveWorkers[$pid]);
            $this->sequentialDelay('worker death');

            $this->performRandomMutations();
            $this->sequentialDelay('mutation');
            $this->verifyKeyspace();
            $this->sequentialDelay('verification');

            $this->logLine('OK', ['remaining_workers' => count($this->aliveWorkers)]);
        }
    }

    private function pickAliveWorker(): int
    {
        $pids = array_keys($this->aliveWorkers);
        sort($pids);

        return $this->rng->pick($pids);
    }

    private function killPid(int $pid, int $signal): void
    {
        if (!function_exists('posix_kill')) {
            $this->fail('posix_kill is required for simple sequential mode');
        }

        $ok = @posix_kill($pid, $signal);
        $signalName = self::signalName($signal);
        $this->recordEvent('kill', [
            'pid' => $pid,
            'signal' => $signalName,
            'ok' => $ok,
        ]);
        $alreadyKilled = isset($this->killedPids[$pid]);
        $this->killedPids[$pid] = true;

        if (!$ok) {
            $this->fail('Failed to signal worker', ['pid' => $pid, 'signal' => $signalName]);
        }

        if (!$alreadyKilled) {
            $this->stats['workers_killed']++;
        }
    }

    private function waitForWorkerDeath(int $pid, bool $allowEscalation): void
    {
        if ($this->waitForWorkerExit($pid)) {
            return;
        }

        if ($allowEscalation) {
            $this->logLine('KILL', ['pid' => $pid, 'signal' => 'SIGKILL', 'escalated' => true], 'warning');
            $this->killPid($pid, 9);

            if ($this->waitForWorkerExit($pid)) {
                return;
            }
        }

        $this->fail('Worker death was not observed before timeout', ['pid' => $pid]);
    }

    private function waitForWorkerExit(int $pid): bool
    {
        $deadline = microtime(true) + max(1.0, $this->config->watchdogTimeoutMs / 1000);

        while (microtime(true) < $deadline) {
            if (!$this->processExists($pid)) {
                $this->recordEvent('death_observed', ['pid' => $pid]);
                $this->logLine('DEAD', ['pid' => $pid]);
                return true;
            }

            usleep(20_000);
        }

        return false;
    }

    private function performRandomMutations(): void
    {
        for ($i = 0; $i < $this->config->mutations; $i++) {
            $choice = $this->rng->int(1, 20);

            if ($choice === 1 && !$this->config->keyspaceIsolated && $this->config->redisServer !== null) {
                $this->performFlushAllMutation();
                continue;
            }

            if ($choice <= 3) {
                $this->performFlushDbMutation();
                continue;
            }

            $this->performIncrByMutation();
        }
    }

    private function performIncrByMutation(): void
    {
        $key = $this->rng->pick($this->keys);
        $amount = $this->rng->int(1, 8);
        $previous = $this->expected[$key] ?? null;
        $value = $this->redis->incrBy($key, $amount);
        $this->expected[$key] = $value;
        $event = [
            'op' => 'INCRBY',
            'key' => $key,
            'amount' => $amount,
            'previous_expected' => $previous,
            'expected' => $value,
            'expected_after' => $value,
        ];
        $this->lastMutation = $event;
        $this->mutations[] = $event;
        $this->stats['mutations']++;
        $this->recordEvent('mutation', $event);
        $this->logLine('MUTATE', $event);
    }

    private function performFlushDbMutation(): void
    {
        if ($this->config->keyspaceIsolated) {
            $this->redis->del($this->keys);
            $event = ['op' => 'DEL_KEYSPACE', 'keys' => count($this->keys)];
        } else {
            $this->redis->flushDb();
            $event = ['op' => 'FLUSHDB'];
        }

        $this->lastMutation = $event;
        $this->mutations[] = $event;
        $this->stats['mutations']++;
        $this->stats['flushdb_mutations']++;
        $this->recordEvent('mutation', $event);
        $this->logLine('MUTATE', $event);
        $this->rebuildKeyspaceAfterFlush();
    }

    private function performFlushAllMutation(): void
    {
        $this->redis->flushAll();
        $event = ['op' => 'FLUSHALL'];
        $this->lastMutation = $event;
        $this->mutations[] = $event;
        $this->stats['mutations']++;
        $this->stats['flushall_mutations']++;
        $this->recordEvent('mutation', $event);
        $this->logLine('MUTATE', $event);
        $this->rebuildKeyspaceAfterFlush();
    }

    private function verifyKeyspace(): void
    {
        $this->stats['verify_scans']++;
        $stale = 0;

        foreach ($this->keys as $key) {
            $stale += $this->verifyKey($key);
        }

        $this->logLine('VERIFY', ['scanned' => count($this->keys)]);
        $this->logLine('VERIFY', ['stale' => $stale]);
    }

    private function verifyKey(string $key): int
    {
        $expected = (string) $this->expected[$key];
        $lastValueMismatch = null;
        $lastRequestFailure = null;
        $stale = 0;

        for ($attempt = 1; $attempt <= $this->config->verifyRetries; $attempt++) {
            $response = $this->tryRequest('/get?key=' . rawurlencode($key));

            if ($response === null) {
                $lastRequestFailure = ['type' => 'request_failed', 'attempt' => $attempt];
                $this->verifyDelay();
                continue;
            }

            $pid = $this->responsePid($response);
            $this->observePid($pid, alive: false);
            $value = $response['value'] === null ? null : (string) $response['value'];
            $event = [
                'pid' => $pid,
                'key' => $key,
                'value' => $value,
                'expected' => $expected,
                'tracked' => $response['tracked'] ?? null,
                'attempt' => $attempt,
            ];
            $this->recordEvent('get', $event);

            if (isset($this->killedPids[$pid])) {
                $this->fail('Killed worker served a request after death was observed', $event);
            }

            if ($value === $expected) {
                return $stale;
            }

            $stale++;
            $lastValueMismatch = $event;
            $this->stats['stale_observations']++;
            $this->staleObservations[] = $event;
            $this->logLine('STALE', $event, 'warning');
            $this->verifyDelay();
        }

        if ($lastValueMismatch !== null) {
            $this->stats['persistent_stale_failures']++;
            $redisValue = $this->redis->get($key);
            $context = [
                'key' => $key,
                'expected' => $expected,
                'actual' => $lastValueMismatch['value'] ?? null,
                'redis_value' => $redisValue,
                'worker_count' => count($this->aliveWorkers),
                'last_mutation' => $this->lastMutation,
                'last_killed_worker' => $this->lastKilledWorker,
                'last_mismatch' => $lastValueMismatch,
            ];

            if ($lastRequestFailure !== null) {
                $context['last_request_failure'] = $lastRequestFailure;
            }

            $this->fail('Persistent stale or mismatched value in simple sequential mode', $context);
        }

        if ($lastRequestFailure !== null) {
            $redisValue = $this->redis->get($key);
            $this->fail('Verification request failed after retries in simple sequential mode', [
                'key' => $key,
                'expected' => $expected,
                'redis_value' => $redisValue,
                'worker_count' => count($this->aliveWorkers),
                'last_mutation' => $this->lastMutation,
                'last_killed_worker' => $this->lastKilledWorker,
                'last_request_failure' => $lastRequestFailure,
            ]);
        }

        return $stale;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function tryRequest(string $path): ?array
    {
        $this->stats['requests']++;

        try {
            return $this->http->getJson($path);
        } catch (RequestException $e) {
            $this->stats['failed_requests']++;
            $this->logger->debug('request failed', [
                'path' => $path,
                'timeout' => $e->timedOut,
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * @param array<string, mixed> $response
     */
    private function responsePid(array $response): int
    {
        if (!isset($response['pid']) || !is_int($response['pid'])) {
            $this->fail('Response did not include an integer pid', ['response' => $response]);
        }

        return $response['pid'];
    }

    private function sequentialDelay(string $reason): void
    {
        if ($this->config->delayUs <= 0) {
            return;
        }

        $this->logger->debug('simple sequential delay', ['reason' => $reason, 'delay_us' => $this->config->delayUs]);
        usleep($this->config->delayUs);
    }

    private function verifyDelay(): void
    {
        if ($this->config->verifyDelayUs <= 0) {
            return;
        }

        $this->logger->debug('verification delay', ['delay_us' => $this->config->verifyDelayUs]);
        usleep($this->config->verifyDelayUs);
    }

    private function cleanupRedisKeys(): void
    {
        $this->redis->del($this->keys);
    }

    private function processExists(int $pid): bool
    {
        if (!function_exists('posix_kill') || !@posix_kill($pid, 0)) {
            return false;
        }

        $stat = @file_get_contents("/proc/{$pid}/stat");

        if (is_string($stat) && preg_match('/^\d+\s+\(.+\)\s+([A-Z])\s/', $stat, $matches)) {
            return $matches[1] !== 'Z';
        }

        return true;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function fail(string $message, array $context = []): never
    {
        $this->failureContext = $context;
        $this->recordEvent('failure', ['message' => $message, 'context' => $context]);
        $this->logger->error('aborting simple sequential fuzz run', ['reason' => $message, 'context' => $context]);

        throw new FuzzerException($message);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function recordEvent(string $type, array $context): void
    {
        $this->events[] = ['time' => sprintf('%.6f', microtime(true)), 'type' => $type] + $context;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logLine(string $tag, array $context, string $level = 'info'): void
    {
        $line = '[' . $tag . ']';

        foreach ($context as $key => $value) {
            if (is_bool($value)) {
                $value = $value ? 'true' : 'false';
            } elseif ($value === null) {
                $value = 'null';
            } elseif (!is_scalar($value)) {
                $value = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            }

            $line .= ' ' . $key . '=' . (string) $value;
        }

        $this->eventLines[] = sprintf('[%.6f] %s', microtime(true), $line);

        if ($level === 'warning') {
            $this->logger->warning($line);
            return;
        }

        $this->logger->info($line);
    }

    private function prepareRrTraceDir(): ?string
    {
        if (!$this->config->rr) {
            return null;
        }

        $root = $this->config->rrTraceDir ?? sys_get_temp_dir();
        $path = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'relay-cache-fuzzer-rr-' . $this->runId;

        if (!is_dir($path) && !mkdir($path, 0777, true)) {
            throw new FuzzerException("Could not create rr trace directory {$path}");
        }

        return $path;
    }

    private function cleanupTempTrace(): void
    {
        if (!$this->config->rr || $this->config->keepTemp || $this->config->rrTraceDir !== null || $this->rrTraceDir === null) {
            return;
        }

        $this->removeTree($this->rrTraceDir);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function writeBundle(string $type, string $reason, array $context, Throwable $throwable): string
    {
        $this->server->drain();

        $path = ReproducerPaths::createBundleDirectory('simple-sequential', $type);

        $commandLine = $this->server->commandLine();
        $output = $this->server->outputText();
        $startup = [
            'seed' => $this->config->seed,
            'timestamp' => date(DATE_ATOM),
            'argv' => array_values(array_map('strval', $_SERVER['argv'] ?? [])),
            'php' => $this->config->php,
            'client' => $this->config->client,
            'server_transport' => $this->config->fpm ? 'fpm' : 'cli',
            'command_line' => $commandLine,
            'runtime_dir' => $this->server->runtimeDirectory(),
            'startup_process_metadata' => $this->server->startupProcessMetadata(),
            'relay_ini' => [
                'relay.max_endpoint_dbs' => $this->config->relayMaxEndpointDbs,
                'relay.max_db_writers' => $this->config->relayMaxDbWriters,
                'relay.cache' => 1,
                'relay.loglevel' => $this->config->captureRelayLogLevel,
                'relay.logfile' => $this->server->relayLogFile(),
            ],
            'workers' => $this->config->workers,
            'keys' => $this->config->keys,
            'mutations_per_worker_death' => $this->config->mutations,
            'signals' => array_map(self::signalName(...), $this->config->signals),
            'redis' => [
                'host' => $this->config->redisHost,
                'port' => $this->config->redisPort,
                'db' => $this->config->redisDb,
            ],
            'delay_us' => $this->config->delayUs,
            'verify_retries' => $this->config->verifyRetries,
            'verify_delay_us' => $this->config->verifyDelayUs,
            'rr' => $this->config->rr,
            'rr_trace_dir' => $this->rrTraceDir,
        ];
        $reproducer = [
            'reproducer_type' => $type,
            'reason' => $reason,
            'exception' => $throwable::class,
            'message' => $throwable->getMessage(),
            'context' => $context,
            'run_id' => $this->runId,
            'stats' => $this->stats,
            'workers' => [
                'observed_pids' => array_map('intval', array_keys($this->workers)),
                'alive_pids' => array_map('intval', array_keys($this->aliveWorkers)),
                'killed_pids' => array_map('intval', array_keys($this->killedPids)),
            ],
            'keys' => $this->keys,
            'expected' => $this->expected,
            'mutations' => $this->mutations,
            'last_mutation' => $this->lastMutation,
            'last_killed_worker' => $this->lastKilledWorker,
            'stale_observations' => $this->staleObservations,
            'events' => $this->events,
        ];

        file_put_contents($path . '/startup.json', json_encode($startup, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
        file_put_contents($path . '/reproducer.json', json_encode($reproducer, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
        file_put_contents($path . '/events.log', implode("\n", $this->eventLines) . ($this->eventLines === [] ? '' : "\n"));
        $this->writeStaleSequenceLog($path, $type, $context);
        file_put_contents($path . '/server.stdout', $output['stdout']);
        file_put_contents($path . '/server.stderr', $output['stderr']);
        ServerProcessMetadataFiles::write($this->server, $path);
        $this->server->copyRuntimeDirectory($path . '/server-runtime');

        if ($this->config->rr && $this->rrTraceDir !== null) {
            $this->preserveRrTrace($path . '/rr');
        }

        return $path;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function writeStaleSequenceLog(string $path, string $type, array $context): void
    {
        if ($type !== ReproducerTypes::STALE_KEY) {
            return;
        }

        $lines = StaleSequenceLog::lines($this->events, $context);

        if ($lines !== []) {
            file_put_contents($path . '/stale-sequence.log', implode("\n", $lines) . "\n");
        }
    }

    private function preserveRrTrace(string $destination): void
    {
        if ($this->rrTraceDir === null || !is_dir($this->rrTraceDir)) {
            file_put_contents(dirname($destination) . '/rr-missing.txt', "rr trace directory was not found\n");
            return;
        }

        if (!$this->waitForRrTraceFinalized($this->rrTraceDir)) {
            file_put_contents(dirname($destination) . '/rr-incomplete.txt', "rr trace still had an incomplete file and was not copied\n");
            return;
        }

        $this->copyTree($this->rrTraceDir, $destination);
    }

    private function waitForRrTraceFinalized(string $traceDir): bool
    {
        $deadline = microtime(true) + 15.0;

        while (microtime(true) < $deadline) {
            if (!$this->treeContainsBasename($traceDir, 'incomplete')) {
                return true;
            }

            usleep(100_000);
        }

        return false;
    }

    private function treeContainsBasename(string $path, string $basename): bool
    {
        if (!is_dir($path)) {
            return false;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
        );

        foreach ($iterator as $item) {
            if ($item->getBasename() === $basename) {
                return true;
            }
        }

        return false;
    }

    private function copyTree(string $source, string $destination): void
    {
        if (!mkdir($destination, 0777, true) && !is_dir($destination)) {
            throw new FuzzerException("Could not create rr bundle directory {$destination}");
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
        );

        foreach ($iterator as $item) {
            $target = $destination . DIRECTORY_SEPARATOR . $iterator->getSubPathName();

            if ($item->isDir()) {
                if (!is_dir($target) && !mkdir($target, 0777, true)) {
                    throw new FuzzerException("Could not create directory {$target}");
                }

                continue;
            }

            if (!copy($item->getPathname(), $target)) {
                throw new FuzzerException("Could not copy rr trace file {$item->getPathname()}");
            }
        }
    }

    private function removeTree(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                rmdir($item->getPathname());
                continue;
            }

            unlink($item->getPathname());
        }

        rmdir($path);
    }

    private static function pickFreePort(string $host): int
    {
        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_server("tcp://{$host}:0", $errno, $errstr);

        if ($socket === false) {
            throw new FuzzerException("Could not pick a free port on {$host}: {$errstr}");
        }

        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        if (!is_string($name) || !preg_match('/:(\d+)$/', $name, $matches)) {
            throw new FuzzerException('Could not parse free port');
        }

        return (int) $matches[1];
    }

    private static function signalName(int $signal): string
    {
        return match ($signal) {
            2 => 'SIGINT',
            3 => 'SIGQUIT',
            6 => 'SIGABRT',
            9 => 'SIGKILL',
            15 => 'SIGTERM',
            default => 'SIG' . $signal,
        };
    }
}

final class ReplayRunner
{
    private Config $config;
    private RedisClient $redis;
    private HttpClient $http;
    private ServerProcess $server;
    private ?RedisServerProcess $redisServer = null;
    private LoggerInterface $logger;
    private string $runId;

    public function __construct(Config $config)
    {
        if ($config->port === 0) {
            $config = $config->withPort($this->pickFreePort($config->host));
        }
        if ($config->redisServer !== null && $config->redisPort === 0) {
            $config = $config->withRedisPort($this->pickFreePort($config->redisHost));
        }

        $this->config = $config;
        $this->logger = LogFactory::create($this->config);
        $this->runId = $this->config->runId ?? 'replay-' . bin2hex(random_bytes(3));
    }

    public function run(): void
    {
        if ($this->config->replayFile === null) {
            throw new FuzzerException('Replay file is required');
        }

        $this->logger->info('starting replay', ['file' => $this->config->replayFile]);
        $raw = file_get_contents($this->config->replayFile);

        if ($raw === false) {
            throw new FuzzerException("Could not read replay file {$this->config->replayFile}");
        }

        $payload = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);

        if (!is_array($payload) || !isset($payload['events']) || !is_array($payload['events'])) {
            throw new FuzzerException('Replay file does not contain an events array');
        }

        try {
            $this->startOwnedRedis();
            $this->redis = new RedisClient(
                $this->config->redisHost,
                $this->config->redisPort,
                $this->config->redisDb,
                $this->config->requestTimeoutMs,
            );
            $this->http = new HttpClient($this->config->host, $this->config->port, $this->config->requestTimeoutMs);
            $this->server = new ServerProcess($this->config, $this->logger, runId: $this->runId);
            $this->server->start();
            $this->waitForPid();

            foreach ($payload['events'] as $event) {
                if (is_array($event)) {
                    $this->replayEvent($event);
                }
            }

            $this->logger->info('replay completed', ['file' => $this->config->replayFile]);
        } finally {
            if (isset($this->server)) {
                $this->server->stop();
            }
            $this->stopOwnedRedis();
        }
    }

    private function startOwnedRedis(): void
    {
        if ($this->config->redisServer === null) {
            return;
        }

        $this->redisServer = new RedisServerProcess($this->config, $this->logger, $this->runId);
        $this->redisServer->start();
    }

    private function stopOwnedRedis(): void
    {
        if ($this->redisServer instanceof RedisServerProcess) {
            $this->redisServer->stop();
            $this->redisServer = null;
        }
    }

    /**
     * @param array<string, mixed> $event
     */
    private function replayEvent(array $event): void
    {
        $type = $event['type'] ?? null;

        if ($type === 'set' && isset($event['key'], $event['value']) && is_string($event['key'])) {
            $this->logger->debug('replay set', ['key' => $event['key'], 'value' => (string) $event['value']]);
            $this->redis->set($event['key'], (string) $event['value']);
            return;
        }

        if ($type === 'incr' && isset($event['key']) && is_string($event['key'])) {
            $this->logger->debug('replay incr', ['key' => $event['key']]);
            $this->redis->incr($event['key']);
            return;
        }

        if ($type === 'warm' && isset($event['key']) && is_string($event['key'])) {
            $reads = isset($event['reads']) && is_int($event['reads']) ? $event['reads'] : $this->config->warmupReads;
            $this->logger->debug('replay warm read', ['key' => $event['key'], 'reads' => $reads]);
            $this->http->getJson('/warm?key=' . rawurlencode($event['key']) . '&n=' . $reads);
            return;
        }

        if ($type === 'get' && isset($event['key']) && is_string($event['key'])) {
            $this->logger->debug('replay get', ['key' => $event['key']]);
            $response = $this->http->getJson('/get?key=' . rawurlencode($event['key']));
            $expected = $event['expected'] ?? null;

            if ($expected !== null && (string) ($response['value'] ?? '') !== (string) $expected) {
                $this->logger->warning('replay mismatch', [
                    'key' => $event['key'],
                    'expected' => (string) $expected,
                    'got' => (string) ($response['value'] ?? 'null'),
                ]);
            }

            return;
        }

        if ($type === 'kill') {
            $pid = isset($event['pid']) && is_int($event['pid']) ? $event['pid'] : null;
            $signal = self::signalNumber(is_string($event['signal'] ?? null) ? $event['signal'] : 'SIGTERM');

            if ($pid !== null && function_exists('posix_kill')) {
                $this->logger->notice('replay kill', ['pid' => $pid, 'signal' => self::signalName($signal)]);
                @posix_kill($pid, $signal);
            }
        }
    }

    private function waitForPid(): void
    {
        $deadline = microtime(true) + 10.0;
        $this->logger->debug('waiting for replay server to respond');

        while (microtime(true) < $deadline) {
            try {
                $this->http->getJson('/pid');
                $this->logger->info('replay server is ready');
                return;
            } catch (RequestException) {
                usleep(50_000);
            }
        }

        throw new FuzzerException('Replay server did not become ready');
    }

    private function pickFreePort(string $host): int
    {
        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_server("tcp://{$host}:0", $errno, $errstr);

        if ($socket === false) {
            throw new FuzzerException("Could not pick a free port on {$host}: {$errstr}");
        }

        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        if (!is_string($name) || !preg_match('/:(\d+)$/', $name, $matches)) {
            throw new FuzzerException('Could not parse free port');
        }

        return (int) $matches[1];
    }

    private static function signalNumber(string $signal): int
    {
        return match (strtoupper($signal)) {
            'SIGINT', 'INT' => 2,
            'SIGKILL', 'KILL' => 9,
            default => 15,
        };
    }

    private static function signalName(int $signal): string
    {
        return match ($signal) {
            2 => 'SIGINT',
            9 => 'SIGKILL',
            15 => 'SIGTERM',
            default => 'SIG' . $signal,
        };
    }
}
