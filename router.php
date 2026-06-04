<?php

declare(strict_types=1);

function relay_fuzz_json(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($payload, JSON_THROW_ON_ERROR) . "\n";
}

function relay_fuzz_param(string $name, string $default = ''): string
{
    $value = $_GET[$name] ?? $default;

    if (!is_scalar($value)) {
        return $default;
    }

    return (string) $value;
}

function relay_fuzz_client(): object
{
    $client = getenv('RELAY_FUZZ_CLIENT');
    $client = $client === false ? 'relay' : strtolower($client);
    $host = getenv('RELAY_FUZZ_REDIS_HOST');
    $port = getenv('RELAY_FUZZ_REDIS_PORT');
    $db = getenv('RELAY_FUZZ_REDIS_DB');
    $host = $host === false ? '127.0.0.1' : $host;
    $port = $port === false ? 6379 : (int) $port;
    $db = $db === false ? 0 : (int) $db;

    if ($client === 'relay') {
        if (!class_exists('Relay\\Relay')) {
            relay_fuzz_json(['error' => 'Relay\\Relay class is not loaded'], 500);
            exit;
        }

        $relay = new Relay\Relay($host, $port);

        if ($db !== 0) {
            $relay->select($db);
        }

        return $relay;
    }

    if ($client === 'redis') {
        if (!class_exists('Redis')) {
            relay_fuzz_json(['error' => 'Redis class is not loaded'], 500);
            exit;
        }

        $redis = new Redis();

        if (!$redis->connect($host, $port)) {
            relay_fuzz_json(['error' => "Could not connect to Redis at {$host}:{$port}"], 500);
            exit;
        }

        if ($db !== 0) {
            $redis->select($db);
        }

        return $redis;
    }

    relay_fuzz_json(['error' => "Unsupported client {$client}"], 500);
    exit;
}

function relay_fuzz_tracked(object $client, string $key): ?bool
{
    if (!method_exists($client, 'isTracked')) {
        return null;
    }

    return (bool) $client->isTracked($key);
}

try {
    $client = relay_fuzz_client();
    $path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
    $pid = getmypid();

    if ($path === '/pid') {
        relay_fuzz_json(['pid' => $pid]);
        return;
    }

    if ($path === '/get') {
        $key = relay_fuzz_param('key');
        $value = $client->get($key);

        relay_fuzz_json([
            'pid' => $pid,
            'key' => $key,
            'value' => $value === false ? null : $value,
            'tracked' => relay_fuzz_tracked($client, $key),
        ]);
        return;
    }

    if ($path === '/warm') {
        $key = relay_fuzz_param('key');
        $reads = max(1, min(100000, (int) relay_fuzz_param('n', '1')));
        $value = null;

        for ($i = 0; $i < $reads; $i++) {
            $value = $client->get($key);
        }

        relay_fuzz_json([
            'pid' => $pid,
            'key' => $key,
            'value' => $value === false ? null : $value,
            'tracked' => relay_fuzz_tracked($client, $key),
            'reads' => $reads,
        ]);
        return;
    }

    if ($path === '/tracked') {
        $key = relay_fuzz_param('key');

        relay_fuzz_json([
            'pid' => $pid,
            'key' => $key,
            'tracked' => relay_fuzz_tracked($client, $key),
        ]);
        return;
    }

    if ($path === '/many') {
        $prefix = relay_fuzz_param('prefix');
        $n = max(1, min(100000, (int) relay_fuzz_param('n', '1')));
        $last = null;

        for ($i = 0; $i < $n; $i++) {
            $last = $client->get($prefix . ':' . $i);
        }

        relay_fuzz_json([
            'pid' => $pid,
            'prefix' => $prefix,
            'value' => $last === false ? null : $last,
            'reads' => $n,
        ]);
        return;
    }

    relay_fuzz_json(['error' => 'not found', 'path' => $path], 404);
} catch (Throwable $e) {
    relay_fuzz_json([
        'error' => $e->getMessage(),
        'type' => $e::class,
        'pid' => getmypid(),
    ], 500);
}
