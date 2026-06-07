<?php

declare(strict_types=1);

namespace MichaelGrunder\RelayCacheFuzzer\Tests;

use MichaelGrunder\RelayCacheFuzzer\Harness\ReductionManager;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__) . '/src/Harness.php';

#[CoversNothing]
final class HarnessTest extends TestCase
{
    public function testHarnessDoesNotForceKeyspaceIsolationForOwnedRedis(): void
    {
        $command = ReductionManager::withHarnessOptions(
            ['bin/relay-cache-fuzzer', '--mode=simple-sequential'],
            123,
            'run-1',
            2,
        );

        self::assertNotContains('--keyspace-isolated', $command);
        self::assertContains('--harness-job-index=2', $command);
    }

    public function testHarnessKeepsKeyspaceIsolationForExternalRedis(): void
    {
        $command = ReductionManager::withHarnessOptions(
            ['bin/relay-cache-fuzzer', '--redis-server=none'],
            123,
            'run-1',
            2,
        );

        self::assertContains('--keyspace-isolated', $command);
    }
}
