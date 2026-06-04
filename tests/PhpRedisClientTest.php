<?php

declare(strict_types=1);

namespace MichaelGrunder\RelayCacheFuzzer\Tests;

use MichaelGrunder\RelayCacheFuzzer\Config;
use MichaelGrunder\RelayCacheFuzzer\Fuzzer;
use MichaelGrunder\RelayCacheFuzzer\SequentialFuzzer;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class PhpRedisClientTest extends TestCase
{
    public function testNormalFuzzerDoesNotReportFailuresWithPhpRedisClient(): void
    {
        self::requirePhpRedisAndRedisServer();

        $config = Config::fromArgv([
            'relay-cache-fuzzer',
            '--client=redis',
            '--php=' . PHP_BINARY,
            '--workers=1',
            '--duration=1',
            '--keys-per-worker=1',
            '--warmup-reads=2',
            '--verify-retries=3',
            '--verify-delay-us=1000',
            '--delay-us=1000',
            '--kill-rate=0',
            '--request-timeout-ms=1000',
            '--watchdog-timeout-ms=5000',
            '--log-level=error',
        ]);

        (new Fuzzer($config))->run();

        self::assertTrue(true);
    }

    public function testSequentialFuzzerDoesNotReportFailuresWithPhpRedisClient(): void
    {
        self::requirePhpRedisAndRedisServer();

        if (!function_exists('posix_kill')) {
            self::markTestSkipped('Sequential mode requires posix_kill().');
        }

        $config = Config::fromArgv([
            'relay-cache-fuzzer',
            '--mode=sequential',
            '--client=redis',
            '--php=' . PHP_BINARY,
            '--workers=2',
            '--keys-per-worker=1',
            '--warmup-reads=2',
            '--verify-retries=3',
            '--verify-delay-us=1000',
            '--delay-us=1000',
            '--request-timeout-ms=1000',
            '--watchdog-timeout-ms=5000',
            '--log-level=error',
        ]);

        (new SequentialFuzzer($config))->run();

        self::assertTrue(true);
    }

    private static function requirePhpRedisAndRedisServer(): void
    {
        if (!extension_loaded('redis') || !class_exists('Redis')) {
            self::markTestSkipped('PhpRedis extension is not loaded.');
        }

        $socket = @stream_socket_client('tcp://127.0.0.1:6379', $errno, $errstr, 0.25);

        if ($socket === false) {
            self::markTestSkipped("Redis is not reachable at 127.0.0.1:6379: {$errstr}");
        }

        fclose($socket);
    }
}
