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
}
