<?php

declare(strict_types=1);

namespace MichaelGrunder\RelayCacheFuzzer\Tests;

use MichaelGrunder\RelayCacheFuzzer\Config;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class ConfigTest extends TestCase
{
    public function testCaptureRelayLogWithoutLevelDefaultsToDebug(): void
    {
        $config = Config::fromArgv([
            'relay-cache-fuzzer',
            '--capture-relay-log',
        ]);

        self::assertSame('debug', $config->captureRelayLogLevel);
    }

    public function testCaptureRelayLogAcceptsRelayLevels(): void
    {
        $config = Config::fromArgv([
            'relay-cache-fuzzer',
            '--capture-relay-log=notice',
        ]);

        self::assertSame('notice', $config->captureRelayLogLevel);
    }

    public function testCaptureRelayLogUnsupportedLevelFallsBackToDebug(): void
    {
        $config = Config::fromArgv([
            'relay-cache-fuzzer',
            '--capture-relay-log=notalevel',
        ]);

        self::assertSame('debug', $config->captureRelayLogLevel);
    }

    public function testRedisDefaultsToEphemeralServerOnFreePort(): void
    {
        $config = Config::fromArgv([
            'relay-cache-fuzzer',
        ]);

        self::assertSame('redis-server', $config->redisServer);
        self::assertSame(0, $config->redisPort);
    }

    public function testHarnessJobIndexOffsetsRedisPort(): void
    {
        $config = Config::fromArgv([
            'relay-cache-fuzzer',
            '--redis-port=7000',
            '--harness-job-index=3',
        ]);

        self::assertSame(7003, $config->redisPort);
    }

    public function testRedisServerNoneUsesExternalRedis(): void
    {
        $config = Config::fromArgv([
            'relay-cache-fuzzer',
            '--redis-server=none',
            '--redis-port=6379',
        ]);

        self::assertNull($config->redisServer);
        self::assertSame(6379, $config->redisPort);
    }
}
