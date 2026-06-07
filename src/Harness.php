<?php

declare(strict_types=1);

namespace MichaelGrunder\RelayCacheFuzzer\Harness;

use PhpTui\Tui\Color\AnsiColor;
use PhpTui\Tui\Display\Display;
use PhpTui\Tui\DisplayBuilder;
use PhpTui\Tui\Extension\Core\Widget\Block\Padding;
use PhpTui\Tui\Extension\Core\Widget\BlockWidget;
use PhpTui\Tui\Extension\Core\Widget\GridWidget;
use PhpTui\Tui\Extension\Core\Widget\Paragraph\Wrap;
use PhpTui\Tui\Extension\Core\Widget\ParagraphWidget;
use PhpTui\Tui\Extension\Core\Widget\Table\TableRow;
use PhpTui\Tui\Extension\Core\Widget\TableWidget;
use PhpTui\Tui\Layout\Constraint;
use PhpTui\Tui\Style\Modifier;
use PhpTui\Tui\Style\Style;
use PhpTui\Tui\Text\Title;
use PhpTui\Tui\Widget\BorderType;
use PhpTui\Tui\Widget\Borders;
use PhpTui\Tui\Widget\Direction;
use PhpTui\Tui\Widget\Widget;
use RuntimeException;
use Random\Engine\Mt19937;
use Random\Randomizer;
use Symfony\Component\Process\Process;

final class HarnessException extends RuntimeException
{
}

final class HarnessConfig
{
    /**
     * @param list<string> $inferiorCommand
     */
    private function __construct(
        public readonly int $jobs,
        public readonly bool $reduce,
        public readonly string $workDir,
        public readonly bool $keepGoing,
        public readonly bool $stopOnFirst,
        public readonly bool $tui,
        public readonly float $statsInterval,
        public readonly int $seed,
        public readonly bool $keepRunArtifacts,
        public readonly array $inferiorCommand,
    ) {
    }

    /**
     * @param list<string> $argv
     */
    public static function fromArgv(array $argv): self
    {
        if (in_array('--help', $argv, true) || in_array('-h', $argv, true)) {
            self::printHelp();
            exit(0);
        }

        $separator = array_search('--', $argv, true);

        if ($separator === false) {
            self::printHelp();
            throw new HarnessException('Missing -- separator before inferior command');
        }

        $harnessArgs = array_slice($argv, 1, (int) $separator - 1);
        $inferiorCommand = array_map('strval', array_slice($argv, (int) $separator + 1));

        if ($inferiorCommand === []) {
            throw new HarnessException('Missing inferior command after --');
        }

        $raw = self::parseOptions($harnessArgs);
        $seed = isset($raw['seed']) ? self::int($raw, 'seed') : random_int(1, PHP_INT_MAX);
        $stopOnFirst = self::bool($raw, 'stop-on-first');

        return new self(
            jobs: max(1, self::int($raw, 'jobs', self::logicalCpuCount())),
            reduce: self::bool($raw, 'reduce'),
            workDir: self::string($raw, 'work-dir', getcwd() ?: '.'),
            keepGoing: !$stopOnFirst,
            stopOnFirst: $stopOnFirst,
            tui: isset($raw['tui']) ? self::bool($raw, 'tui') : !isset($raw['no-tui']) && self::stdoutIsTty(),
            statsInterval: max(0.1, self::float($raw, 'stats-interval', 1.0)),
            seed: $seed,
            keepRunArtifacts: self::bool($raw, 'keep-run-artifacts'),
            inferiorCommand: $inferiorCommand,
        );
    }

    /**
     * @param list<string> $args
     * @return array<string, string|bool>
     */
    private static function parseOptions(array $args): array
    {
        $out = [];
        $count = count($args);

        for ($i = 0; $i < $count; $i++) {
            $arg = $args[$i];

            if ($arg === '--help' || $arg === '-h') {
                self::printHelp();
                exit(0);
            }

            if (!str_starts_with($arg, '--')) {
                throw new HarnessException("Unexpected harness argument: {$arg}");
            }

            $arg = substr($arg, 2);
            $eq = strpos($arg, '=');

            if ($eq !== false) {
                $out[substr($arg, 0, $eq)] = substr($arg, $eq + 1);
                continue;
            }

            if ($i + 1 < $count && !str_starts_with($args[$i + 1], '--')) {
                $out[$arg] = $args[++$i];
            } else {
                $out[$arg] = true;
            }
        }

        if (isset($out['keep-going']) && isset($out['stop-on-first'])) {
            throw new HarnessException('--keep-going and --stop-on-first are mutually exclusive');
        }

        return $out;
    }

    private static function printHelp(): void
    {
        echo <<<'HELP'
Relay cache fuzzer harness

Usage:
  bin/harness [harness options] -- bin/relay-cache-fuzzer [fuzzer options]

Harness options:
  --jobs=N              Number of inferiors to run simultaneously. Default: logical CPUs.
  --reduce              Reduce integer template parameters after flaws.
  --work-dir=PATH       Harness state root. Default: current directory.
  --keep-going          Continue after failures. This is the default.
  --stop-on-first       Stop all running jobs after the first confirmed flaw.
  --tui                 Enable fullscreen dashboard.
  --no-tui              Plain event logging.
  --stats-interval=N    Dashboard refresh interval in seconds. Default: 1.
  --seed=N              Harness RNG seed.
  --keep-run-artifacts  Preserve per-run artifacts under artifacts/runs.

Inferior exit statuses:
  0 = normal completion
  1 = infrastructure or setup error
  2 = flaw detected with a reproducer

Template variables:
  Inferior arguments may contain {{NAME}} or {{NAME=INTEGER}} placeholders.
  Known fuzzer variables include COMMANDS, WORKERS, KEYS, MUTATIONS, and
  VERIFY_RETRIES. Additional integer variables can be supplied with the
  {{NAME=INTEGER}} form.

HELP;
    }

    /**
     * @param array<string, string|bool> $raw
     */
    private static function string(array $raw, string $key, string $default): string
    {
        if (!isset($raw[$key])) {
            return $default;
        }

        if ($raw[$key] === true) {
            throw new HarnessException("Option --{$key} requires a value");
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
            throw new HarnessException("Option --{$key} must be an integer");
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
            throw new HarnessException("Option --{$key} must be numeric");
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

    private static function stdoutIsTty(): bool
    {
        return defined('STDOUT') && function_exists('stream_isatty') && stream_isatty(STDOUT);
    }

    private static function logicalCpuCount(): int
    {
        $candidates = [
            trim((string) @shell_exec('getconf _NPROCESSORS_ONLN 2>/dev/null')),
            trim((string) @shell_exec('nproc 2>/dev/null')),
        ];

        foreach ($candidates as $candidate) {
            if (preg_match('/^\d+$/', $candidate) && (int) $candidate > 0) {
                return (int) $candidate;
            }
        }

        return 1;
    }
}

final class TemplateValues
{
    /** @var array<string, int> */
    private array $values;
    /** @var list<string> */
    private array $templateNames;

    /**
     * @param array<string, int> $values
     * @param list<string> $templateNames
     */
    private function __construct(array $values, array $templateNames)
    {
        $this->values = $values;
        $this->templateNames = $templateNames;
    }

    /**
     * @param list<string> $args
     */
    public static function fromInferiorCommand(array $args): self
    {
        $values = self::knownDefaults();
        $optionValues = self::parseIntegerOptions($args);

        foreach ($optionValues as $name => $value) {
            $values[$name] = $value;
        }

        if (isset($optionValues['COMMANDS_PER_WORKER'])) {
            $values['COMMANDS'] = $optionValues['COMMANDS_PER_WORKER'];
        }

        $placeholders = self::placeholders($args);

        foreach ($placeholders as $name => $default) {
            if ($default !== null) {
                $values[$name] = $default;
                continue;
            }

            if (!isset($values[$name])) {
                throw new HarnessException("Template variable {{$name}} needs an integer source; use {{$name}=N} for new variables");
            }
        }

        $templateNames = array_keys($placeholders);
        sort($templateNames);

        return new self($values, $templateNames);
    }

    /**
     * @return array<string, int>
     */
    public function all(): array
    {
        return $this->values;
    }

    public function get(string $name): int
    {
        if (!isset($this->values[$name])) {
            throw new HarnessException("Unknown template variable {$name}");
        }

        return $this->values[$name];
    }

    public function with(string $name, int $value): self
    {
        $values = $this->values;
        $values[$name] = max(1, $value);

        return new self($values, $this->templateNames);
    }

    /**
     * @return list<string>
     */
    public function reducibleNames(): array
    {
        return $this->templateNames;
    }

    /**
     * @param list<string> $args
     * @return list<string>
     */
    public function render(array $args): array
    {
        $rendered = [];

        foreach ($args as $arg) {
            $rendered[] = preg_replace_callback(
                '/\{\{([A-Z][A-Z0-9_]*)(?:=(\d+))?\}\}/',
                function (array $matches): string {
                    $name = $matches[1];

                    if (!isset($this->values[$name])) {
                        throw new HarnessException("Unknown template variable {$name}");
                    }

                    return (string) $this->values[$name];
                },
                $arg,
            );
        }

        return $rendered;
    }

    /**
     * @param list<string> $args
     * @return array<string, int|null>
     */
    private static function placeholders(array $args): array
    {
        $out = [];

        foreach ($args as $arg) {
            if (!preg_match_all('/\{\{([A-Z][A-Z0-9_]*)(?:=(\d+))?\}\}/', $arg, $matches, PREG_SET_ORDER)) {
                continue;
            }

            foreach ($matches as $match) {
                $out[$match[1]] = isset($match[2]) ? (int) $match[2] : null;
            }
        }

        return $out;
    }

    /**
     * @param list<string> $args
     * @return array<string, int>
     */
    private static function parseIntegerOptions(array $args): array
    {
        $values = [];
        $count = count($args);

        for ($i = 0; $i < $count; $i++) {
            $arg = $args[$i];

            if (!str_starts_with($arg, '--')) {
                continue;
            }

            $option = substr($arg, 2);
            $value = null;
            $eq = strpos($option, '=');

            if ($eq !== false) {
                $value = substr($option, $eq + 1);
                $option = substr($option, 0, $eq);
            } elseif ($i + 1 < $count && preg_match('/^\d+$/', $args[$i + 1])) {
                $value = $args[++$i];
            }

            if ($value === null || !preg_match('/^\d+$/', $value)) {
                continue;
            }

            $name = strtoupper(str_replace('-', '_', $option));
            $values[$name] = (int) $value;
        }

        return $values;
    }

    /**
     * @return array<string, int>
     */
    private static function knownDefaults(): array
    {
        return [
            'COMMANDS' => 10000,
            'WORKERS' => 2,
            'KEYS' => 100,
            'MUTATIONS' => 1,
            'VERIFY_RETRIES' => 8,
        ];
    }
}

final class RingBuffer
{
    /** @var list<string> */
    private array $items = [];

    public function __construct(private readonly int $limit)
    {
    }

    public function push(string $item): void
    {
        $this->items[] = $item;

        if (count($this->items) > $this->limit) {
            array_shift($this->items);
        }
    }

    /**
     * @return list<string>
     */
    public function all(): array
    {
        return $this->items;
    }
}

final class HarnessEventLog
{
    private RingBuffer $events;

    public function __construct(private readonly bool $plainLogging)
    {
        $this->events = new RingBuffer(30);
    }

    public function add(string $message): void
    {
        $line = date('Y-m-d H:i:s') . ' ' . $message;
        $this->events->push($line);

        if ($this->plainLogging) {
            fwrite(STDERR, $line . PHP_EOL);
        }
    }

    /**
     * @return list<string>
     */
    public function all(): array
    {
        return $this->events->all();
    }
}

final class Job
{
    public string $state = 'idle';
    public ?Process $process = null;
    public ?int $pid = null;
    public ?float $startTime = null;
    public int $runCount = 0;
    public int $failures = 0;
    public int $seed = 0;
    public string $runId = '';
    public string $runDir = '';
    public string $stdoutPath = '';
    public string $stderrPath = '';
    public ?string $lastReproducer = null;
    public RingBuffer $stdoutTail;
    public RingBuffer $stderrTail;
    /** @var list<string> */
    public array $command = [];

    public function __construct(public readonly int $id)
    {
        $this->stdoutTail = new RingBuffer(20);
        $this->stderrTail = new RingBuffer(20);
    }
}

final class CampaignStats
{
    public float $startedAt;
    public int $totalRuns = 0;
    public int $totalFailures = 0;
    public ?float $lastFailureAt = null;
    public ?int $lastFailureJob = null;
    public ?string $lastFailurePath = null;
    public int $totalReproducers = 0;
    public int $completedReductions = 0;

    public function __construct()
    {
        $this->startedAt = microtime(true);
    }
}

final class ArtifactManager
{
    private int $nextFailureId;

    public function __construct(private readonly HarnessConfig $config)
    {
        $this->ensureDirectory($this->failureRoot());
        $this->ensureDirectory($this->runRoot());
        $this->nextFailureId = $this->discoverNextFailureId();
    }

    public function runRoot(): string
    {
        return $this->config->workDir . DIRECTORY_SEPARATOR . 'artifacts' . DIRECTORY_SEPARATOR . 'runs';
    }

    public function failureRoot(): string
    {
        return $this->config->workDir . DIRECTORY_SEPARATOR . 'artifacts' . DIRECTORY_SEPARATOR . 'failures';
    }

    public function createRunDirectory(Job $job): string
    {
        $path = $this->runRoot() . DIRECTORY_SEPARATOR . sprintf('job-%03d-run-%06d', $job->id, $job->runCount + 1);
        $this->ensureDirectory($path);

        return $path;
    }

    public function cleanupRunDirectory(Job $job): bool
    {
        if ($job->runDir === '') {
            return true;
        }

        $runRoot = $this->runRoot();
        $runDir = $job->runDir;

        if (!str_starts_with($runDir, $runRoot . DIRECTORY_SEPARATOR)) {
            return false;
        }

        if (!is_dir($runDir)) {
            return true;
        }

        return $this->removeTree($runDir);
    }

    /**
     * @param array<string, int> $reductionValues
     */
    public function recordFailure(Job $job, int $exitCode, array $reductionValues): string
    {
        $path = $this->failureRoot() . DIRECTORY_SEPARATOR . sprintf('%06d', $this->nextFailureId++);
        $this->ensureDirectory($path);

        $reproducerPath = $this->resolvePath($job->lastReproducer);
        $metadata = [
            'timestamp' => date(DATE_ATOM),
            'harness_seed' => $this->config->seed,
            'inferior_seed' => $job->seed,
            'job_id' => $job->id,
            'run_id' => $job->runId,
            'exit_code' => $exitCode,
            'reduction_parameters' => $reductionValues,
            'reproducer_location' => $job->lastReproducer,
            'command' => $job->command,
            'run_directory' => $job->runDir,
        ];

        file_put_contents($path . DIRECTORY_SEPARATOR . 'metadata.json', json_encode($metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
        file_put_contents($path . DIRECTORY_SEPARATOR . 'command.txt', self::formatCommand($job->command) . "\n");
        $this->copyIfExists($job->stdoutPath, $path . DIRECTORY_SEPARATOR . 'stdout.log');
        $this->copyIfExists($job->stderrPath, $path . DIRECTORY_SEPARATOR . 'stderr.log');

        if ($reproducerPath !== null && is_file($reproducerPath)) {
            $this->ensureDirectory($path . DIRECTORY_SEPARATOR . 'reproducer');
            copy($reproducerPath, $path . DIRECTORY_SEPARATOR . 'reproducer' . DIRECTORY_SEPARATOR . basename($reproducerPath));
        } elseif ($reproducerPath !== null && is_dir($reproducerPath)) {
            $this->copyTree($reproducerPath, $path . DIRECTORY_SEPARATOR . 'reproducer');
        }

        return $path;
    }

    /**
     * @param list<string> $command
     */
    public static function formatCommand(array $command): string
    {
        return implode(' ', array_map(self::quote(...), $command));
    }

    private static function quote(string $arg): string
    {
        if ($arg !== '' && preg_match('/^[A-Za-z0-9_@%+=:,.\/-]+$/', $arg)) {
            return $arg;
        }

        return "'" . str_replace("'", "'\"'\"'", $arg) . "'";
    }

    private function discoverNextFailureId(): int
    {
        $max = 0;

        foreach (glob($this->failureRoot() . DIRECTORY_SEPARATOR . '[0-9][0-9][0-9][0-9][0-9][0-9]', GLOB_ONLYDIR) ?: [] as $path) {
            $max = max($max, (int) basename($path));
        }

        return $max + 1;
    }

    private function resolvePath(?string $path): ?string
    {
        if ($path === null || $path === '') {
            return null;
        }

        if (str_starts_with($path, DIRECTORY_SEPARATOR)) {
            return $path;
        }

        return (getcwd() ?: '.') . DIRECTORY_SEPARATOR . $path;
    }

    private function copyIfExists(string $source, string $destination): void
    {
        if (is_file($source)) {
            copy($source, $destination);
        }
    }

    private function copyTree(string $source, string $destination): void
    {
        $this->ensureDirectory($destination);

        foreach (scandir($source) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $from = $source . DIRECTORY_SEPARATOR . $entry;
            $to = $destination . DIRECTORY_SEPARATOR . $entry;

            if (is_dir($from) && !is_link($from)) {
                $this->copyTree($from, $to);
            } elseif (is_file($from)) {
                copy($from, $to);
            }
        }
    }

    private function removeTree(string $path): bool
    {
        foreach (scandir($path) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $child = $path . DIRECTORY_SEPARATOR . $entry;

            if (is_dir($child) && !is_link($child)) {
                if (!$this->removeTree($child)) {
                    return false;
                }
            } elseif (is_file($child) || is_link($child)) {
                if (!unlink($child)) {
                    return false;
                }
            }
        }

        return rmdir($path);
    }

    private function ensureDirectory(string $path): void
    {
        if (!is_dir($path) && !mkdir($path, 0777, true) && !is_dir($path)) {
            throw new HarnessException("Could not create directory {$path}");
        }
    }
}

final class ReductionTask
{
    public string $state = 'queued';
    public ?Process $process = null;
    public ?string $activeVariable = null;
    public int $low = 1;
    public int $high = 1;
    public int $best = 1;
    public int $attempt = 0;
    public ?int $attemptValue = null;
    public string $runId = '';
    public string $stdoutPath = '';
    public string $stderrPath = '';
    /** @var list<string> */
    public array $variables;
    /** @var list<array<string, mixed>> */
    public array $attempts = [];

    /**
     * @param list<string> $baseCommand
     */
    public function __construct(
        public readonly int $id,
        public readonly string $failurePath,
        public readonly array $baseCommand,
        public TemplateValues $values,
        public readonly int $seed,
    ) {
        $this->variables = array_values(array_filter(
            $values->reducibleNames(),
            fn (string $name): bool => $values->get($name) > 1,
        ));
    }
}

final class ReductionManager
{
    /** @var list<ReductionTask> */
    private array $queue = [];
    /** @var list<ReductionTask> */
    private array $active = [];
    private int $nextId = 1;

    public function __construct(
        private readonly HarnessConfig $config,
        private readonly HarnessEventLog $events,
        private readonly CampaignStats $stats,
    ) {
    }

    /**
     * @param list<string> $command
     */
    public function enqueue(string $failurePath, array $command, TemplateValues $values, int $seed): void
    {
        $task = new ReductionTask($this->nextId++, $failurePath, $command, $values, $seed);
        $this->queue[] = $task;
        $this->events->add("Reduction queued id={$task->id} failure={$failurePath}");
    }

    public function tick(): void
    {
        while ($this->active === [] && $this->queue !== []) {
            $task = array_shift($this->queue);
            $this->startNextVariable($task);
        }

        foreach ($this->active as $index => $task) {
            if ($task->process instanceof Process && $task->process->isRunning()) {
                continue;
            }

            $this->finishAttempt($task);

            if ($task->state === 'completed') {
                unset($this->active[$index]);
                $this->active = array_values($this->active);
            }
        }
    }

    public function activeCount(): int
    {
        return count($this->active);
    }

    public function pendingCount(): int
    {
        return count($this->queue);
    }

    public function stopAll(): void
    {
        foreach ($this->active as $task) {
            if ($task->process instanceof Process && $task->process->isRunning()) {
                $task->process->stop(2.0, 15);
            }
        }
    }

    /**
     * @return list<ReductionTask>
     */
    public function activeTasks(): array
    {
        return $this->active;
    }

    private function startNextVariable(ReductionTask $task): void
    {
        $name = array_shift($task->variables);

        if ($name === null) {
            $this->complete($task);
            return;
        }

        $task->activeVariable = $name;
        $task->low = 1;
        $task->high = $task->values->get($name);
        $task->best = $task->high;
        $task->state = 'running';
        $this->active[] = $task;
        $this->events->add("Reduction started id={$task->id} variable={$name} initial={$task->high}");
        $this->startAttempt($task);
    }

    private function startAttempt(ReductionTask $task): void
    {
        if ($task->activeVariable === null) {
            $this->complete($task);
            return;
        }

        if ($task->low >= $task->high) {
            $task->values = $task->values->with($task->activeVariable, $task->best);
            $this->events->add("Reduction variable completed id={$task->id} variable={$task->activeVariable} value={$task->best}");
            $task->state = 'between-variables';
            $this->active = array_values(array_filter($this->active, static fn (ReductionTask $active): bool => $active !== $task));
            $this->startNextVariable($task);
            return;
        }

        $task->attempt++;
        $mid = intdiv($task->low + $task->high, 2);
        $task->attemptValue = max(1, $mid);
        $attemptValues = $task->values->with($task->activeVariable, $task->attemptValue);
        $task->runId = sprintf('harness-reduce-%d-attempt-%d', $task->id, $task->attempt);
        $dir = $this->config->workDir . DIRECTORY_SEPARATOR . 'artifacts' . DIRECTORY_SEPARATOR . 'reductions' . DIRECTORY_SEPARATOR . sprintf('%06d', $task->id);

        if (!is_dir($dir) && !mkdir($dir, 0777, true) && !is_dir($dir)) {
            throw new HarnessException("Could not create reduction directory {$dir}");
        }

        $task->stdoutPath = $dir . DIRECTORY_SEPARATOR . sprintf('attempt-%03d.stdout', $task->attempt);
        $task->stderrPath = $dir . DIRECTORY_SEPARATOR . sprintf('attempt-%03d.stderr', $task->attempt);
        $command = self::withHarnessOptions($attemptValues->render($task->baseCommand), $task->seed, $task->runId, 0);
        $process = new Process($command, getcwd() ?: null, null, null, null);
        $process->setTimeout(null);
        $task->process = $process;
        $process->start(function (string $type, string $data) use ($task): void {
            file_put_contents($type === Process::OUT ? $task->stdoutPath : $task->stderrPath, $data, FILE_APPEND);
        });
        $this->events->add("Reduction attempt id={$task->id} variable={$task->activeVariable} value={$task->attemptValue} pid={$process->getPid()}");
    }

    private function finishAttempt(ReductionTask $task): void
    {
        $process = $task->process;

        if (!$process instanceof Process) {
            $this->complete($task);
            return;
        }

        $exitCode = $process->getExitCode() ?? 1;
        $reproduced = $exitCode === 2;
        $task->attempts[] = [
            'variable' => $task->activeVariable,
            'value' => $task->attemptValue,
            'exit_code' => $exitCode,
            'reproduced' => $reproduced,
        ];

        if ($reproduced && $task->attemptValue !== null) {
            $task->best = $task->attemptValue;
            $task->high = $task->attemptValue;
        } elseif ($task->attemptValue !== null) {
            $task->low = $task->attemptValue + 1;
        }

        $this->startAttempt($task);
    }

    private function complete(ReductionTask $task): void
    {
        $task->state = 'completed';
        $this->stats->completedReductions++;
        $dir = $this->config->workDir . DIRECTORY_SEPARATOR . 'artifacts' . DIRECTORY_SEPARATOR . 'reductions' . DIRECTORY_SEPARATOR . sprintf('%06d', $task->id);

        if (!is_dir($dir) && !mkdir($dir, 0777, true) && !is_dir($dir)) {
            throw new HarnessException("Could not create reduction directory {$dir}");
        }

        file_put_contents($dir . DIRECTORY_SEPARATOR . 'results.json', json_encode([
            'id' => $task->id,
            'failure_path' => $task->failurePath,
            'seed' => $task->seed,
            'final_values' => $task->values->all(),
            'attempts' => $task->attempts,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
        $this->events->add("Reduction completed id={$task->id} results={$dir}");
    }

    /**
     * @param list<string> $command
     * @return list<string>
     */
    public static function withHarnessOptions(array $command, int $seed, string $runId, ?int $jobIndex = null): array
    {
        $command[] = '--seed=' . $seed;
        $command[] = '--run-id=' . $runId;

        if (self::usesExternalRedis($command)) {
            $command[] = '--keyspace-isolated';
        }

        if ($jobIndex !== null) {
            $command[] = '--harness-job-index=' . $jobIndex;
        }

        return $command;
    }

    /**
     * @param list<string> $command
     */
    private static function usesExternalRedis(array $command): bool
    {
        $count = count($command);

        for ($i = 0; $i < $count; $i++) {
            $arg = $command[$i];

            if ($arg === '--redis-server=none' || $arg === '--redis-server=') {
                return true;
            }

            if ($arg === '--redis-server' && strtolower($command[$i + 1] ?? '') === 'none') {
                return true;
            }
        }

        return false;
    }
}

final class Dashboard
{
    private ?Display $display = null;

    public function __construct(private readonly HarnessConfig $config)
    {
    }

    /**
     * @param list<Job> $jobs
     */
    public function render(CampaignStats $stats, array $jobs, HarnessEventLog $events, TemplateValues $values, ReductionManager $reductions): void
    {
        if (!$this->config->tui) {
            return;
        }

        if (!$this->display instanceof Display) {
            $this->enter();
        }

        if (!$this->display instanceof Display) {
            return;
        }

        $elapsed = max(0.001, microtime(true) - $stats->startedAt);
        $hours = $elapsed / 3600;
        $activeJobs = count(array_filter($jobs, static fn (Job $job): bool => $job->state === 'running'));

        $this->display->draw(
            GridWidget::default()
                ->direction(Direction::Vertical)
                ->constraints(
                    Constraint::length(6),
                    Constraint::length(7),
                    Constraint::min(8),
                    Constraint::length(8),
                )
                ->widgets(
                    $this->summaryPanel($elapsed, $hours, $activeJobs, count($jobs), $stats),
                    GridWidget::default()
                        ->direction(Direction::Horizontal)
                        ->constraints(Constraint::percentage(50), Constraint::percentage(50))
                        ->widgets(
                            $this->failurePanel($stats),
                            $this->knobPanel($values, $reductions),
                        ),
                    GridWidget::default()
                        ->direction(Direction::Horizontal)
                        ->constraints(Constraint::percentage(58), Constraint::percentage(42))
                        ->widgets(
                            $this->jobsPanel($jobs),
                            $this->reductionsPanel($stats, $reductions),
                        ),
                    $this->eventsPanel($events),
                )
        );
    }

    public function enter(): void
    {
        if ($this->config->tui) {
            fwrite(STDOUT, "\033[?25l");
            $this->display ??= DisplayBuilder::default()->fullscreen()->build();
            $this->display->clear();
        }
    }

    public function leave(): void
    {
        if ($this->config->tui) {
            $this->display?->clear();
            fwrite(STDOUT, "\033[?25h\033[0m\n");
            $this->display = null;
        }
    }

    private function summaryPanel(float $elapsed, float $hours, int $activeJobs, int $jobCount, CampaignStats $stats): Widget
    {
        return $this->panel('Relay Cache Fuzzer Harness', $this->spacedTable(TableWidget::default()
            ->widths(Constraint::percentage(23), Constraint::percentage(23), Constraint::percentage(23), Constraint::percentage(23))
            ->rows(
                TableRow::fromStrings('elapsed', 'runs done', 'reproducers', 'active jobs'),
                TableRow::fromStrings(
                    self::duration($elapsed),
                    number_format($stats->totalRuns),
                    number_format($stats->totalReproducers),
                    "{$activeJobs}/{$jobCount}",
                ),
                TableRow::fromStrings('runs/hour', 'flaws/hour', 'failures', 'completed reductions'),
                TableRow::fromStrings(
                    number_format($stats->totalRuns / $hours, 1),
                    number_format($stats->totalFailures / $hours, 2),
                    number_format($stats->totalFailures),
                    number_format($stats->completedReductions),
                ),
            )));
    }

    private function failurePanel(CampaignStats $stats): Widget
    {
        return $this->panel('Reproducers', ParagraphWidget::fromString(implode("\n", [
            'count: ' . number_format($stats->totalReproducers),
            'last time: ' . ($stats->lastFailureAt === null ? 'none' : date('Y-m-d H:i:s', (int) $stats->lastFailureAt)),
            'last job: ' . ($stats->lastFailureJob === null ? 'none' : (string) $stats->lastFailureJob),
            'last reproducer: ' . ($stats->lastFailurePath ?? 'none'),
        ]))->wrap(Wrap::WordTrimmed));
    }

    private function knobPanel(TemplateValues $values, ReductionManager $reductions): Widget
    {
        $all = $values->all();
        $rows = [];

        foreach ($this->knobNames($values) as $name) {
            $rows[] = TableRow::fromStrings($name, isset($all[$name]) ? number_format($all[$name]) : 'n/a', $this->reductionStateFor($name, $reductions));
        }

        return $this->panel('Current Knobs', $this->spacedTable(TableWidget::default()
            ->widths(Constraint::percentage(38), Constraint::percentage(18), Constraint::percentage(36))
            ->header(TableRow::fromStrings('name', 'value', 'reduction'))
            ->rows(...array_slice($rows, 0, 12))));
    }

    /**
     * @param list<Job> $jobs
     */
    private function jobsPanel(array $jobs): Widget
    {
        $rows = [];

        foreach ($jobs as $job) {
            $runtime = $job->startTime === null ? '-' : self::duration(microtime(true) - $job->startTime);
            $rows[] = TableRow::fromStrings(
                (string) $job->id,
                $job->pid === null ? '-' : (string) $job->pid,
                $job->state,
                $runtime,
                (string) $job->seed,
                number_format($job->runCount),
                number_format($job->failures),
            );
        }

        return $this->panel('Inferiors', $this->spacedTable(TableWidget::default()
            ->widths(
                Constraint::percentage(7),
                Constraint::percentage(12),
                Constraint::percentage(15),
                Constraint::percentage(15),
                Constraint::percentage(20),
                Constraint::percentage(10),
                Constraint::percentage(10),
            )
            ->header(TableRow::fromStrings('job', 'pid', 'state', 'runtime', 'seed', 'runs', 'fails'))
            ->rows(...$rows)));
    }

    private function reductionsPanel(CampaignStats $stats, ReductionManager $reductions): Widget
    {
        $rows = [
            TableRow::fromStrings('active', (string) $reductions->activeCount(), 'completed', number_format($stats->completedReductions)),
            TableRow::fromStrings('pending', (string) $reductions->pendingCount(), '', ''),
        ];

        foreach ($reductions->activeTasks() as $task) {
            $rows[] = TableRow::fromStrings(
                '#' . $task->id,
                $task->activeVariable ?? 'none',
                'try ' . ($task->attemptValue === null ? '-' : (string) $task->attemptValue),
                "best {$task->best} [{$task->low},{$task->high}]",
            );
        }

        return $this->panel('Reduction', $this->spacedTable(TableWidget::default()
            ->widths(Constraint::percentage(18), Constraint::percentage(28), Constraint::percentage(20), Constraint::percentage(28))
            ->rows(...array_slice($rows, 0, 10))));
    }

    private function eventsPanel(HarnessEventLog $events): Widget
    {
        return $this->panel('Recent Events', ParagraphWidget::fromString(implode("\n", array_slice($events->all(), -6)))->wrap(Wrap::WordTrimmed));
    }

    private function panel(string $title, Widget $widget): Widget
    {
        return BlockWidget::default()
            ->borders(Borders::ALL)
            ->borderType(BorderType::Rounded)
            ->titles(Title::fromString($title))
            ->titleStyle(Style::default()->fg(AnsiColor::LightCyan)->addModifier(Modifier::BOLD))
            ->borderStyle(Style::default()->fg(AnsiColor::DarkGray))
            ->padding(Padding::horizontal(1))
            ->widget($widget);
    }

    private function spacedTable(TableWidget $table): TableWidget
    {
        $table->columnSpacing = 1;

        return $table;
    }

    /**
     * @return list<string>
     */
    private function knobNames(TemplateValues $values): array
    {
        $names = array_unique([
            ...$values->reducibleNames(),
            'COMMANDS',
            'COMMANDS_PER_WORKER',
            'WORKERS',
            'KEYS',
            'MUTATIONS',
            'VERIFY_RETRIES',
        ]);
        sort($names);

        $values = $values->all();

        return array_values(array_filter($names, static fn (string $name): bool => isset($values[$name])));
    }

    private function reductionStateFor(string $name, ReductionManager $reductions): string
    {
        foreach ($reductions->activeTasks() as $task) {
            if ($task->activeVariable === $name) {
                return sprintf('trying %s best %d', $task->attemptValue === null ? '-' : (string) $task->attemptValue, $task->best);
            }
        }

        return in_array($name, $this->activeReductionNames($reductions), true) ? 'queued' : '';
    }

    /**
     * @return list<string>
     */
    private function activeReductionNames(ReductionManager $reductions): array
    {
        $names = [];

        foreach ($reductions->activeTasks() as $task) {
            foreach ($task->variables as $name) {
                $names[] = $name;
            }
        }

        return $names;
    }

    private static function duration(float $seconds): string
    {
        $seconds = max(0, (int) $seconds);
        $hours = intdiv($seconds, 3600);
        $minutes = intdiv($seconds % 3600, 60);
        $secs = $seconds % 60;

        return sprintf('%02d:%02d:%02d', $hours, $minutes, $secs);
    }
}

final class Coordinator
{
    private TemplateValues $templateValues;
    private ArtifactManager $artifacts;
    private HarnessEventLog $events;
    private CampaignStats $stats;
    private ReductionManager $reductions;
    private Dashboard $dashboard;
    private Randomizer $randomizer;
    /** @var list<Job> */
    private array $jobs = [];
    private bool $stopping = false;

    public function __construct(private readonly HarnessConfig $config)
    {
        $this->templateValues = TemplateValues::fromInferiorCommand($config->inferiorCommand);
        $this->artifacts = new ArtifactManager($config);
        $this->events = new HarnessEventLog(!$config->tui);
        $this->stats = new CampaignStats();
        $this->reductions = new ReductionManager($config, $this->events, $this->stats);
        $this->dashboard = new Dashboard($config);
        $this->randomizer = new Randomizer(new Mt19937($config->seed));
    }

    public function run(): void
    {
        $this->installSignalHandlers();
        $this->events->add("Harness started jobs={$this->config->jobs} seed={$this->config->seed}");
        $this->dashboard->enter();
        $lastRender = 0.0;

        try {
            for ($i = 1; $i <= $this->config->jobs; $i++) {
                $job = new Job($i);
                $this->jobs[] = $job;
                $this->startJob($job);
            }

            while (!$this->stopping || $this->hasRunningJobs() || $this->reductions->activeCount() > 0) {
                $this->pollSignals();
                $this->tickJobs();
                $this->reductions->tick();

                $now = microtime(true);
                if ($now - $lastRender >= $this->config->statsInterval) {
                    $this->dashboard->render($this->stats, $this->jobs, $this->events, $this->templateValues, $this->reductions);
                    $lastRender = $now;
                }

                if (($this->stopping || !$this->config->keepGoing) && !$this->hasRunningJobs() && $this->reductions->activeCount() === 0 && $this->reductions->pendingCount() === 0) {
                    break;
                }

                usleep(100_000);
            }
        } finally {
            $this->stopAllJobs();
            $this->reductions->stopAll();
            $this->dashboard->render($this->stats, $this->jobs, $this->events, $this->templateValues, $this->reductions);
            $this->dashboard->leave();
        }
    }

    private function startJob(Job $job): void
    {
        $job->state = 'starting';
        $job->seed = $this->randomInt();
        $job->runId = sprintf('harness-job-%d-run-%d-%s', $job->id, $job->runCount + 1, $this->randomHex(4));
        $job->lastReproducer = null;
        $job->stdoutTail = new RingBuffer(20);
        $job->stderrTail = new RingBuffer(20);
        $job->runDir = $this->artifacts->createRunDirectory($job);
        $job->stdoutPath = $job->runDir . DIRECTORY_SEPARATOR . 'stdout.log';
        $job->stderrPath = $job->runDir . DIRECTORY_SEPARATOR . 'stderr.log';
        $job->command = ReductionManager::withHarnessOptions(
            $this->templateValues->render($this->config->inferiorCommand),
            $job->seed,
            $job->runId,
            $job->id - 1,
        );
        file_put_contents($job->runDir . DIRECTORY_SEPARATOR . 'command.txt', ArtifactManager::formatCommand($job->command) . "\n");

        $process = new Process($job->command, getcwd() ?: null, null, null, null);
        $process->setTimeout(null);
        $job->process = $process;
        $job->startTime = microtime(true);
        $process->start(function (string $type, string $data) use ($job): void {
            $path = $type === Process::OUT ? $job->stdoutPath : $job->stderrPath;
            file_put_contents($path, $data, FILE_APPEND);
            $this->recordOutput($job, $type, $data);
        });
        $job->pid = $process->getPid();
        $job->state = 'running';
        $this->events->add("Job started id={$job->id} pid={$job->pid} seed={$job->seed} run_id={$job->runId}");
    }

    private function tickJobs(): void
    {
        foreach ($this->jobs as $job) {
            if (!$job->process instanceof Process || $job->state !== 'running') {
                continue;
            }

            if ($job->process->isRunning()) {
                continue;
            }

            $this->finishJob($job);
        }
    }

    private function finishJob(Job $job): void
    {
        $exitCode = $job->process instanceof Process ? ($job->process->getExitCode() ?? 1) : 1;
        $job->runCount++;
        $this->stats->totalRuns++;
        $job->pid = null;

        if ($exitCode === 0) {
            $this->events->add("Job completed id={$job->id} runs={$job->runCount}");
        } elseif ($exitCode === 2) {
            $job->failures++;
            $this->stats->totalFailures++;
            $this->stats->lastFailureAt = microtime(true);
            $this->stats->lastFailureJob = $job->id;
            $failurePath = $this->artifacts->recordFailure($job, $exitCode, $this->templateValues->all());
            $this->stats->lastFailurePath = $failurePath;
            $this->stats->totalReproducers++;
            $this->events->add("Failure detected job={$job->id} path={$failurePath}");

            if ($this->config->reduce) {
                $this->reductions->enqueue($failurePath, $this->config->inferiorCommand, $this->templateValues, $job->seed);
            }

            if ($this->config->stopOnFirst) {
                $this->stopping = true;
                $this->cleanupRunArtifacts($job);
                $this->stopAllJobs();
                return;
            }
        } else {
            $this->events->add("Job infrastructure error id={$job->id} exit={$exitCode}");
        }

        $this->cleanupRunArtifacts($job);

        if (!$this->stopping && $this->config->keepGoing) {
            $this->startJob($job);
        } else {
            $job->state = 'stopped';
        }
    }

    private function stopAllJobs(): void
    {
        foreach ($this->jobs as $job) {
            if ($job->process instanceof Process && $job->process->isRunning()) {
                $job->state = 'stopping';
                $job->process->stop(2.0, 15);
                $job->state = 'stopped';
                $job->pid = null;
                $this->cleanupRunArtifacts($job);
            }
        }
    }

    private function cleanupRunArtifacts(Job $job): void
    {
        if ($this->config->keepRunArtifacts) {
            return;
        }

        $runDir = $job->runDir;

        if ($this->artifacts->cleanupRunDirectory($job)) {
            $this->events->add("Cleaned run artifacts job={$job->id} dir={$runDir}");
        } else {
            $this->events->add("Could not clean run artifacts job={$job->id} dir={$runDir}");
        }
    }

    private function hasRunningJobs(): bool
    {
        foreach ($this->jobs as $job) {
            if ($job->process instanceof Process && $job->process->isRunning()) {
                return true;
            }
        }

        return false;
    }

    private function recordOutput(Job $job, string $type, string $data): void
    {
        foreach (preg_split('/\r?\n/', $data) ?: [] as $line) {
            if ($line === '') {
                continue;
            }

            if ($type === Process::OUT) {
                $job->stdoutTail->push($line);
            } else {
                $job->stderrTail->push($line);
            }

            if (preg_match('/reproducer=([^\s]+)/', $line, $matches)) {
                $job->lastReproducer = $matches[1];
            }
        }
    }

    private function randomInt(): int
    {
        return $this->randomizer->getInt(1, PHP_INT_MAX);
    }

    private function randomHex(int $bytes): string
    {
        $hex = '';

        for ($i = 0; $i < $bytes; $i++) {
            $hex .= str_pad(dechex($this->randomizer->getInt(0, 255)), 2, '0', STR_PAD_LEFT);
        }

        return $hex;
    }

    private function installSignalHandlers(): void
    {
        if (!function_exists('pcntl_signal')) {
            return;
        }

        pcntl_signal(SIGINT, function (): void {
            $this->events->add('Stopping after SIGINT');
            $this->stopping = true;
        });
        pcntl_signal(SIGTERM, function (): void {
            $this->events->add('Stopping after SIGTERM');
            $this->stopping = true;
        });
    }

    private function pollSignals(): void
    {
        if (function_exists('pcntl_signal_dispatch')) {
            pcntl_signal_dispatch();
        }
    }
}
