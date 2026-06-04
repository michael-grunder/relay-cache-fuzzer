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

try {
    if (!class_exists('Relay\\Relay')) {
        relay_fuzz_json(['error' => 'Relay\\Relay class is not loaded'], 500);
        return;
    }

    $host = getenv('RELAY_FUZZ_REDIS_HOST');
    $port = getenv('RELAY_FUZZ_REDIS_PORT');
    $db = getenv('RELAY_FUZZ_REDIS_DB');

    $relay = new Relay\Relay(
        $host === false ? '127.0.0.1' : $host,
        $port === false ? 6379 : (int) $port,
    );

    if ($db !== false && (int) $db !== 0) {
        $relay->select((int) $db);
    }

    $path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
    $pid = getmypid();

    if ($path === '/pid') {
        relay_fuzz_json(['pid' => $pid]);
        return;
    }

    if ($path === '/get') {
        $key = relay_fuzz_param('key');
        $value = $relay->get($key);

        relay_fuzz_json([
            'pid' => $pid,
            'key' => $key,
            'value' => $value === false ? null : $value,
            'tracked' => $relay->isTracked($key),
        ]);
        return;
    }

    if ($path === '/warm') {
        $key = relay_fuzz_param('key');
        $reads = max(1, min(100000, (int) relay_fuzz_param('n', '1')));
        $value = null;

        for ($i = 0; $i < $reads; $i++) {
            $value = $relay->get($key);
        }

        relay_fuzz_json([
            'pid' => $pid,
            'key' => $key,
            'value' => $value === false ? null : $value,
            'tracked' => $relay->isTracked($key),
            'reads' => $reads,
        ]);
        return;
    }

    if ($path === '/tracked') {
        $key = relay_fuzz_param('key');

        relay_fuzz_json([
            'pid' => $pid,
            'key' => $key,
            'tracked' => $relay->isTracked($key),
        ]);
        return;
    }

    if ($path === '/many') {
        $prefix = relay_fuzz_param('prefix');
        $n = max(1, min(100000, (int) relay_fuzz_param('n', '1')));
        $last = null;

        for ($i = 0; $i < $n; $i++) {
            $last = $relay->get($prefix . ':' . $i);
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
