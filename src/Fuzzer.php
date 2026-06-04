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
    private RingBuffer $stdout;
    private RingBuffer $stderr;

    public function __construct(
        private readonly Config $config,
        private readonly LoggerInterface $logger,
    ) {
        $this->stdout = new RingBuffer(200);
        $this->stderr = new RingBuffer(200);
    }

    public function start(): void
    {
        $router = dirname(__DIR__) . '/router.php';
        $command = [
            $this->config->php,
            '-d', 'relay.max_endpoint_dbs=' . $this->config->relayMaxEndpointDbs,
            '-d', 'relay.max_db_writers=' . $this->config->relayMaxDbWriters,
            '-d', 'relay.cache=1',
            '-S', $this->config->host . ':' . $this->config->port,
            $router,
        ];

        $this->process = new Process(
            $command,
            dirname(__DIR__),
            [
                'PHP_CLI_SERVER_WORKERS' => (string) $this->config->workers,
                'RELAY_FUZZ_REDIS_HOST' => $this->config->redisHost,
                'RELAY_FUZZ_REDIS_PORT' => (string) $this->config->redisPort,
                'RELAY_FUZZ_REDIS_DB' => (string) $this->config->redisDb,
            ],
        );
        $this->process->setTimeout(null);
        $this->logger->info('starting PHP CLI server', [
            'host' => $this->config->host,
            'port' => $this->config->port,
            'workers' => $this->config->workers,
        ]);
        $this->logger->debug('server command line', ['command' => $this->process->getCommandLine()]);
        $this->process->start();

        $this->logger->debug('server parent started', ['pid' => $this->process->getPid()]);
    }

    public function drain(): void
    {
        $this->pushLines($this->stdout, $this->process->getIncrementalOutput(), 'stdout');
        $this->pushLines($this->stderr, $this->process->getIncrementalErrorOutput(), 'stderr');
    }

    public function isRunning(): bool
    {
        $this->drain();

        return $this->process->isRunning();
    }

    public function parentPid(): ?int
    {
        return $this->process->getPid();
    }

    public function commandLine(): string
    {
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

    public function stop(): void
    {
        if (isset($this->process) && $this->process->isRunning()) {
            $this->logger->info('stopping PHP CLI server', ['parent_pid' => $this->process->getPid()]);
            $this->process->stop(1.0, 15);
        }
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
}

final class Fuzzer
{
    private Config $config;
    private Rng $rng;
    private RedisClient $redis;
    private HttpClient $http;
    private ServerProcess $server;
    private LoggerInterface $logger;
    private string $runId;
    private ?string $failurePath = null;
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
        $this->config = $config->port === 0 ? $config->withPort(self::pickFreePort($config->host)) : $config;
        $this->logger = LogFactory::create($this->config);
        $this->rng = new Rng($this->config->seed);
        $this->runId = dechex($this->config->seed) . '-' . bin2hex(random_bytes(3));
        $this->lastRequests = new RingBuffer(100);
        $this->lastMutations = new RingBuffer(100);
        $this->lastStale = new RingBuffer(100);
        $this->lastSuccessAt = microtime(true);
    }

    public function run(): void
    {
        $this->logger->info('starting fuzz run', [
            'seed' => $this->config->seed,
            'run_id' => $this->runId,
            'server' => "http://{$this->config->host}:{$this->config->port}",
            'workers' => $this->config->workers,
        ]);

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
        $this->server = new ServerProcess($this->config, $this->logger);

        try {
            $this->server->start();
            $this->waitUntilReady();
            $this->deterministicSmoke();

            $deadline = microtime(true) + $this->config->durationSeconds;

            while (microtime(true) < $deadline) {
                $this->iteration();
            }

            $this->cleanupRedisKeys();
            $this->server->drain();
            $this->logger->info('completed fuzz run', [
                'iterations' => $this->stats['iterations'],
                'requests' => $this->stats['total_requests'],
                'stale_observations' => $this->stats['stale_observations'],
            ]);
        } catch (Throwable $e) {
            $path = $this->failurePath ?? $this->writeReproducer('exception', ['message' => $e->getMessage()]);
            $this->logger->error('fuzz run failed', ['error' => $e->getMessage(), 'reproducer' => $path]);
            throw new FuzzerException($e->getMessage() . "\nreproducer={$path}", previous: $e);
        } finally {
            $this->server->stop();
        }
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
            $value = $this->redis->incr($key);
            $this->expected[$key] = $value;
            $event = ['type' => 'incr', 'key' => $key, 'value' => (string) $value];
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
            $lastMismatch = null;

            for ($attempt = 1; $attempt <= $this->config->verifyRetries; $attempt++) {
                $this->logger->debug('doing verification read', [
                    'key' => $key,
                    'expected' => $expected,
                    'attempt' => $attempt,
                ]);
                $response = $this->tryRequest('/get?key=' . rawurlencode($key));

                if ($response === null) {
                    $lastMismatch = ['type' => 'request_failed', 'attempt' => $attempt];
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
                    $lastMismatch = null;
                    break;
                }

                $lastMismatch = $event;
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

            if ($lastMismatch !== null) {
                $this->stats['persistent_stale_failures']++;
                $redisValue = $this->redis->get($key);
                $this->logger->error('persistent mismatch after verification retries', [
                    'key' => $key,
                    'expected' => $expected,
                    'redis_value' => $redisValue,
                ]);
                $this->abort('Persistent stale or mismatched value', [
                    'key' => $key,
                    'expected' => $expected,
                    'redis_value' => $redisValue,
                    'last_mismatch' => $lastMismatch,
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
            $this->lastRequests->push([
                'path' => $path,
                'ok' => true,
                'elapsed_ms' => $elapsedMs,
                'pid' => $response['pid'] ?? null,
            ]);
            $this->logger->debug('request completed', [
                'path' => $path,
                'elapsed_ms' => $elapsedMs,
                'pid' => $response['pid'] ?? null,
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
        $this->failurePath = $this->writeReproducer($message, $context);

        throw new FuzzerException("{$message}\nreproducer={$this->failurePath}");
    }

    /**
     * @param array<string, mixed> $context
     */
    private function writeReproducer(string $reason, array $context): string
    {
        $this->server->drain();
        $path = getcwd() . '/relay-cache-fuzzer-failure-' . $this->runId . '-' . date('Ymd-His') . '.json';
        $payload = [
            'reason' => $reason,
            'context' => $context,
            'seed' => $this->config->seed,
            'php' => $this->config->php,
            'run_id' => $this->runId,
            'server' => [
                'host' => $this->config->host,
                'port' => $this->config->port,
                'parent_pid' => $this->server->parentPid(),
                'command_line' => $this->server->commandLine(),
                'output' => $this->server->tails(),
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
            ],
            'stats' => $this->stats,
            'last_requests' => $this->lastRequests->all(),
            'last_mutations' => $this->lastMutations->all(),
            'last_stale_observations' => $this->lastStale->all(),
            'events' => $this->events,
        ];

        file_put_contents($path, json_encode($payload, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n");
        $this->logger->error('wrote failure reproducer', ['path' => $path, 'reason' => $reason]);

        return $path;
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

final class ReplayRunner
{
    private Config $config;
    private RedisClient $redis;
    private HttpClient $http;
    private ServerProcess $server;
    private LoggerInterface $logger;

    public function __construct(Config $config)
    {
        $this->config = $config->port === 0 ? $config->withPort($this->pickFreePort($config->host)) : $config;
        $this->logger = LogFactory::create($this->config);
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

        $this->redis = new RedisClient(
            $this->config->redisHost,
            $this->config->redisPort,
            $this->config->redisDb,
            $this->config->requestTimeoutMs,
        );
        $this->http = new HttpClient($this->config->host, $this->config->port, $this->config->requestTimeoutMs);
        $this->server = new ServerProcess($this->config, $this->logger);

        try {
            $this->server->start();
            $this->waitForPid();

            foreach ($payload['events'] as $event) {
                if (is_array($event)) {
                    $this->replayEvent($event);
                }
            }

            $this->logger->info('replay completed', ['file' => $this->config->replayFile]);
        } finally {
            $this->server->stop();
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
