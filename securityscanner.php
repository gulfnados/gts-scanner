<?php
declare(strict_types=1);

const APP_NAME = 'Gulfnados Technology Systems (GTS) Malware Scanner';
const APP_VERSION = '3.1.0';
const SHORT_NAME = 'GTS Malware Scanner';
const TIMEZONE = 'Asia/Dubai';

/* ---- Branding shown in the footer ------------------------------------ */
const COMPANY_NAME      = 'Gulfnados Technology Systems';
const COMPANY_URL       = 'https://www.gulfnados.com';
const COMPANY_URL_LABEL = 'www.gulfnados.com';
// Optional. Leave empty to hide the support line entirely.
const SUPPORT_EMAIL     = '';
const PHP_CLI_PATH = '/usr/bin/php';
const REPORT_RETENTION_DAYS = 30;
const SESSION_TIMEOUT = 1800;

// Default only. The dashboard toggle (saved in config.json) overrides this.
const AUTO_QUARANTINE = true;

// Run scans as a detached background process so the browser request returns
// immediately and can never hit the web server's execution-time limit.
// Set to false only if your host blocks background processes.
const BACKGROUND_SCAN = false;

// Memory guards for large sites.
const DASHBOARD_MEMORY_LIMIT = '256M';  // raised only if the current limit is lower
const SCANNER_MEMORY_LIMIT = '512M';    // memory_limit handed to the AMWScan process
const DISABLE_CHECKSUM = false;         // true = skip the checksum verifier: much less memory on huge sites
const MAX_FINDINGS_STORED = 1000;       // cap findings kept in the JSON report
const MAX_FINDING_DETAIL = 4000;        // cap the technical-details block per finding
const MAX_FINDINGS_RENDERED = 200;      // cap findings drawn on the page

date_default_timezone_set(TIMEZONE);
@set_time_limit(0);
@ini_set('max_execution_time', '0');

function memoryBytes(string $value): int
{
    $value = trim($value);
    if ($value === '') return 0;
    if ($value === '-1') return PHP_INT_MAX;
    $number = (int)$value;
    return match (strtolower(substr($value, -1))) {
        'g' => $number * 1073741824,
        'm' => $number * 1048576,
        'k' => $number * 1024,
        default => $number,
    };
}
/** Raise the memory limit, never lower it. */
function raiseMemoryLimit(string $target): void
{
    $current = (string)ini_get('memory_limit');
    if (trim($current) === '-1') return;
    if (memoryBytes($current) >= memoryBytes($target)) return;
    @ini_set('memory_limit', $target);
}
raiseMemoryLimit(DASHBOARD_MEMORY_LIMIT);

$root = realpath(__DIR__) ?: __DIR__;
$scanner = $root . DIRECTORY_SEPARATOR . 'scanner.php';
$self = realpath(__FILE__) ?: __FILE__;
$installationId = substr(hash('sha256', $root), 0, 12);

function privateBase(string $root): string
{
    $candidates = [];
    $home = getenv('HOME');
    if (is_string($home) && $home !== '') $candidates[] = $home;
    if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
        $user = @posix_getpwuid(posix_geteuid());
        if (is_array($user) && !empty($user['dir'])) $candidates[] = (string)$user['dir'];
    }
    if (!empty($_SERVER['DOCUMENT_ROOT'])) {
        $docRoot = realpath((string)$_SERVER['DOCUMENT_ROOT']);
        if ($docRoot) $candidates[] = dirname($docRoot);
    }
    $candidates[] = dirname($root);
    foreach (array_unique($candidates) as $candidate) {
        if (is_dir($candidate) && is_writable($candidate)) return rtrim($candidate, '/\\');
    }
    return $root;
}

// The background CLI process is told exactly which data folder to use, so it
// can never end up somewhere different from the web request that started it.
$dataDirOverride = '';
if (PHP_SAPI === 'cli') {
    foreach ($argv ?? [] as $cliArg) {
        if (str_starts_with((string)$cliArg, '--data=')) $dataDirOverride = substr((string)$cliArg, 7);
    }
}
if ($dataDirOverride !== '' && !is_dir($dataDirOverride)) @mkdir($dataDirOverride, 0700, true);
$dataDir = ($dataDirOverride !== '' && is_dir($dataDirOverride))
    ? rtrim(str_replace('\\', '/', $dataDirOverride), '/')
    : privateBase($root) . DIRECTORY_SEPARATOR . '.security-scanner-' . $installationId;

$reportsDir = $dataDir . DIRECTORY_SEPARATOR . 'reports';
$quarantineDir = $dataDir . DIRECTORY_SEPARATOR . 'quarantine';
$configFile = $dataDir . DIRECTORY_SEPARATOR . 'config.json';
$statusFile = $dataDir . DIRECTORY_SEPARATOR . 'status.json';
$manifestFile = $dataDir . DIRECTORY_SEPARATOR . 'quarantine.json';
$exclusionsFile = $dataDir . DIRECTORY_SEPARATOR . 'exclusions.txt';
$lockFile = $dataDir . DIRECTORY_SEPARATOR . 'scan.lock';

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function ensureDir(string $path): void
{
    if (!is_dir($path) && !@mkdir($path, 0700, true) && !is_dir($path)) {
        throw new RuntimeException('Unable to create directory: ' . $path);
    }
    @chmod($path, 0700);
}
function readJson(string $path, array $fallback = []): array
{
    $raw = is_file($path) ? @file_get_contents($path) : false;
    if (!is_string($raw) || $raw === '') return $fallback;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $fallback;
}
function writeJson(string $path, array $data): void
{
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (!is_string($json) || @file_put_contents($path, $json . PHP_EOL, LOCK_EX) === false) {
        throw new RuntimeException('Unable to write: ' . $path);
    }
    @chmod($path, 0600);
}
function stripAnsi(string $value): string
{
    $clean = preg_replace('/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -\/]*[@-~])/', '', $value);
    return is_string($clean) ? $clean : $value;
}
function slash(string $path): string
{
    return str_replace('\\', '/', $path);
}
function cliPhp(): string
{
    if (is_file(PHP_CLI_PATH) && is_executable(PHP_CLI_PATH)) return PHP_CLI_PATH;
    return defined('PHP_BINARY') && is_string(PHP_BINARY) && PHP_BINARY !== '' ? PHP_BINARY : 'php';
}
/**
 * Every plausible location of a real PHP *CLI* binary.
 * Under PHP-FPM, PHP_BINARY points at the php-fpm daemon, which cannot run a
 * script - that alone breaks background scans on a lot of hosts.
 * Supports: cPanel, CloudLinux, LiteSpeed, Plesk, XAMPP, WAMP, local PHP installs
 */
function phpCandidates(): array
{
    $list = [];
    $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

    // Explicit config or built-in constant
    if (PHP_CLI_PATH !== '') $list[] = PHP_CLI_PATH;
    if (PHP_SAPI === 'cli' && defined('PHP_BINARY') && PHP_BINARY !== '') $list[] = PHP_BINARY;
    if (defined('PHP_BINDIR')) $list[] = PHP_BINDIR . DIRECTORY_SEPARATOR . 'php' . ($isWindows ? '.exe' : '');

    // Standard Linux/Unix paths
    if (!$isWindows) {
        foreach (['/usr/local/bin/php', '/usr/bin/php', '/bin/php', '/usr/local/php/bin/php'] as $path) $list[] = $path;
        foreach (glob('/opt/cpanel/ea-php*/root/usr/bin/php') ?: [] as $path) $list[] = $path;   // cPanel
        foreach (glob('/opt/alt/php*/usr/bin/php') ?: [] as $path) $list[] = $path;              // CloudLinux
        foreach (glob('/usr/local/lsws/lsphp*/bin/php') ?: [] as $path) $list[] = $path;         // LiteSpeed
        foreach (glob('/opt/plesk/php/*/bin/php') ?: [] as $path) $list[] = $path;               // Plesk
        foreach (glob('/opt/xampp/bin/php*') ?: [] as $path) $list[] = $path;                   // XAMPP Linux
        foreach (glob('/opt/lampp/bin/php*') ?: [] as $path) $list[] = $path;                   // LAMP
    }

    // Windows paths: XAMPP, WAMP, Laragon. glob() on Windows wants forward slashes.
    if ($isWindows) {
        // Derive the drive the site actually lives on, then the usual suspects.
        $drives = [];
        $docRoot = (string)($_SERVER['DOCUMENT_ROOT'] ?? '');
        if (preg_match('/^([A-Za-z]:)/', $docRoot, $m)) $drives[] = strtoupper($m[1]);
        if (preg_match('/^([A-Za-z]:)/', __DIR__, $m)) $drives[] = strtoupper($m[1]);
        foreach (['C:', 'D:', 'E:'] as $d) $drives[] = $d;
        foreach (array_unique($drives) as $drive) {
            foreach ([
                '/xampp/php/php.exe',
                '/xampp64/php/php.exe',
                '/wamp/bin/php/php.exe',
                '/wamp64/bin/php/php.exe',
                '/laragon/bin/php/php.exe',
                '/php/php.exe',
            ] as $tail) $list[] = $drive . $tail;
            // Versioned layouts: wamp64/bin/php/php8.2.4/php.exe, laragon/bin/php/php-8.2/php.exe
            foreach ([
                '/wamp/bin/php/php*/php.exe',
                '/wamp64/bin/php/php*/php.exe',
                '/laragon/bin/php/php*/php.exe',
            ] as $pattern) {
                foreach (glob($drive . $pattern, GLOB_NOSORT) ?: [] as $path) $list[] = $path;
            }
        }
        // XAMPP installed next to the web root: C:\xampp\htdocs\site -> C:\xampp\php\php.exe
        $probe = __DIR__;
        for ($i = 0; $i < 5 && $probe !== '' && $probe !== dirname($probe); $i++) {
            $list[] = $probe . DIRECTORY_SEPARATOR . 'php' . DIRECTORY_SEPARATOR . 'php.exe';
            $probe = dirname($probe);
        }
    }

    // Whatever is on PATH.
    if (hasCommand('php')) {
        $which = trim((string)@shell_exec($isWindows ? 'where php 2>NUL' : 'command -v php 2>/dev/null'));
        foreach (preg_split('/\r?\n/', $which) ?: [] as $line) {
            $line = trim($line);
            if ($line !== '') $list[] = $line;
        }
    }

    // Filter to files that exist. On Windows is_executable() is unreliable for
    // .exe under some SAPIs, so existence is enough there - phpWorks() is the
    // real gate either way.
    $clean = [];
    foreach ($list as $path) {
        $path = (string)$path;
        if ($path === '' || !@is_file($path)) continue;
        if (!$isWindows && !@is_executable($path)) continue;
        $clean[] = $path;
    }
    return array_values(array_unique($clean));
}
/** Actually run the binary - existing and executable is not the same as usable. */
function phpWorks(string $binary): bool
{
    if ($binary === '' || !execAllowed()) return false;
    if (!@is_file($binary)) return false;
    $output = []; $code = 1;
    // Windows cmd.exe needs NUL; -r arguments must not be single-quoted there.
    $null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
    $snippet = DIRECTORY_SEPARATOR === '\\' ? '"echo \"GTSOK\";"' : escapeshellarg('echo "GTSOK";');
    $bin = DIRECTORY_SEPARATOR === '\\' ? '"' . $binary . '"' : escapeshellarg($binary);
    @exec($bin . ' -r ' . $snippet . ' 2>' . $null, $output, $code);
    return $code === 0 && in_array('GTSOK', array_map('trim', $output), true);
}
/** Find a working PHP CLI binary and remember it in config.json. */
function detectCliPhp(array &$config, string $configFile): string
{
    $cached = (string)($config['php_cli'] ?? '');
    if ($cached !== '' && @is_executable($cached) && phpWorks($cached)) return $cached;
    foreach (phpCandidates() as $candidate) {
        if (!phpWorks($candidate)) continue;
        $config['php_cli'] = $candidate;
        try { writeJson($configFile, $config); } catch (Throwable) {}
        return $candidate;
    }
    return cliPhp();
}
function execAllowed(): bool
{
    if (!function_exists('exec')) return false;
    return !in_array('exec', array_map('trim', explode(',', (string)ini_get('disable_functions'))), true);
}
function hasCommand(string $name): bool
{
    if (!function_exists('shell_exec')) return false;
    if (in_array('shell_exec', array_map('trim', explode(',', (string)ini_get('disable_functions'))), true)) return false;
    if (DIRECTORY_SEPARATOR === '\\') {
        $out = @shell_exec('where ' . $name . ' 2>NUL');
    } else {
        $out = @shell_exec('command -v ' . escapeshellarg($name) . ' 2>/dev/null');
    }
    return is_string($out) && trim($out) !== '';
}
function humanSize(int $bytes): string
{
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return round($bytes / 1024, 1) . ' KB';
    return round($bytes / 1048576, 2) . ' MB';
}
function normalizePath(string $path, string $root): string
{
    $path = trim(slash($path));
    $root = rtrim(slash($root), '/');
    if ($path === '') return '';
    if (!str_starts_with($path, '/') && preg_match('/^[A-Za-z]:\//', $path) !== 1) {
        $path = $root . '/' . ltrim($path, '/');
    }
    $parts = [];
    foreach (explode('/', $path) as $part) {
        if ($part === '' || $part === '.') continue;
        if ($part === '..') { array_pop($parts); continue; }
        $parts[] = $part;
    }
    return '/' . implode('/', $parts);
}

/* ------------------------------------------------------------------
 * Custom scan path
 * ------------------------------------------------------------------ */

function allowedBases(string $root): array
{
    $bases = [];
    $home = getenv('HOME');
    if (is_string($home) && $home !== '') $bases[] = realpath($home);
    if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
        $user = @posix_getpwuid(posix_geteuid());
        if (is_array($user) && !empty($user['dir'])) $bases[] = realpath((string)$user['dir']);
    }
    if (!empty($_SERVER['DOCUMENT_ROOT'])) $bases[] = realpath((string)$_SERVER['DOCUMENT_ROOT']);
    $bases[] = $root;

    $clean = [];
    foreach ($bases as $base) {
        if (!is_string($base) || $base === '' || !is_dir($base)) continue;
        $base = rtrim(slash($base), '/');
        if ($base === '' || $base === '/') continue;
        $clean[] = $base;
    }
    return array_values(array_unique($clean));
}
function withinBases(string $path, array $bases): bool
{
    $path = rtrim(slash($path), '/');
    if ($path === '') return false;
    foreach ($bases as $base) {
        if ($path === $base || str_starts_with($path, $base . '/')) return true;
    }
    return false;
}
/**
 * Validate a scan path. Returns the canonical path, or null with $error set.
 * The boundary check is enforced when the path is SET from the browser; a path
 * already stored in config.json passed that check when it was saved.
 */
function resolveScanPath(string $candidate, array $bases, ?string &$error = null, bool $enforceBoundary = true): ?string
{
    $error = null;
    $candidate = trim($candidate);
    if ($candidate === '') return null;
    if (str_contains($candidate, "\0")) { $error = 'Invalid characters in path.'; return null; }
    $real = realpath($candidate);
    if ($real === false || !is_dir($real)) { $error = 'Path does not exist or is not a directory: ' . $candidate; return null; }
    if (!is_readable($real)) { $error = 'Path is not readable by the web server user: ' . $real; return null; }
    $real = rtrim(slash($real), '/');
    if ($real === '') $real = '/';
    if ($enforceBoundary && !withinBases($real, $bases)) {
        $error = 'Path is outside the allowed area. Allowed: ' . implode(', ', $bases);
        return null;
    }
    return $real;
}

function readExclusions(string $file): array
{
    $lines = is_file($file) ? (file($file, FILE_IGNORE_NEW_LINES) ?: []) : [];
    $result = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || str_contains($line, "\0")) continue;
        $result[] = $line;
    }
    return array_values(array_unique($result));
}
function saveExclusions(string $file, array $values): bool
{
    $clean = [];
    foreach ($values as $value) {
        $value = trim(str_replace(["\r", "\n", "\0"], '', (string)$value));
        if ($value === '' || str_contains($value, '../') || str_contains($value, '..\\')) continue;
        $clean[] = $value;
    }
    $written = @file_put_contents($file, implode(PHP_EOL, array_values(array_unique($clean))) . PHP_EOL, LOCK_EX);
    if ($written === false) return false;
    @chmod($file, 0600);
    clearstatcache(true, $file);
    return is_readable($file);
}
function exclusionMatches(string $file, string $rule, string $root): bool
{
    $file = normalizePath($file, $root);
    $rule = normalizePath($rule, $root);
    if ($file === '' || $rule === '') return false;
    if (str_contains($rule, '*')) {
        $pattern = '~^' . str_replace('\\*', '.*', preg_quote($rule, '~')) . '$~i';
        return preg_match($pattern, $file) === 1;
    }
    return $file === $rule || str_starts_with($file, rtrim($rule, '/') . '/');
}
function countFiles(string $directory): int
{
    if (!is_dir($directory)) return 0;
    $count = 0;
    try {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $item) if ($item->isFile()) $count++;
    } catch (Throwable) {}
    return $count;
}

/* ------------------------------------------------------------------
 * Quarantine: manifest, move, restore, delete
 * ------------------------------------------------------------------ */

/**
 * The path to act on. AMWScan reports absolute paths in 'file'; the signature
 * engine reports a display-friendly relative path and keeps the real one in
 * 'absolute_path'. Without this, selecting a signature finding for quarantine
 * resolved to a path that does not exist, and every one of them rendered as
 * "Quarantined or removed" because is_file() on the relative path was false.
 */
/** Footer CSS. Both screens have their own <style> block, so this is
 *  emitted into each of them - defining it twice by hand is how they drift. */
function footerCss(): string
{
    return <<<'CSS'
/* site footer */
.sitefoot{margin-top:30px;padding:20px 16px 24px;border-top:1px solid var(--border);display:flex;flex-direction:column;align-items:center;gap:9px;text-align:center}
.sitefoot-compact{margin-top:22px;padding:16px 12px 4px;gap:7px}
.sf-brand{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:9px;font-size:13.5px;font-weight:700;color:var(--text)}
.sf-mark{width:17px;height:17px;flex:0 0 auto;color:var(--brand)}
.sf-co{letter-spacing:.1px}
/* the highlight: brand-tinted pill, underlined on hover, never wider than the screen */
.sf-link{display:inline-flex;align-items:center;gap:5px;max-width:100%;padding:5px 12px;border-radius:999px;
  background:var(--brand-soft);color:var(--brand);border:1px solid var(--border);
  font-weight:800;font-size:13px;letter-spacing:.2px;text-decoration:none;overflow-wrap:anywhere;
  transition:background .15s,border-color .15s,transform .15s}
.sf-link svg{width:11px;height:11px;flex:0 0 auto;opacity:.75}
.sf-link:hover,.sf-link:focus-visible{background:var(--brand);color:var(--brand-ink);border-color:var(--brand);transform:translateY(-1px)}
.sf-link:hover svg,.sf-link:focus-visible svg{opacity:1}
.sf-link:focus-visible{outline:2px solid var(--brand);outline-offset:2px}
.sf-meta{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:4px 8px;color:var(--muted);font-size:11.5px;line-height:1.6}
.sf-meta b{color:var(--text);font-weight:700}
.sf-sep{opacity:.45}
.sf-fine{font-size:11px;opacity:.85}
.sf-id{font-family:var(--mono);font-size:10.5px;background:var(--surface2);border:1px solid var(--border);border-radius:5px;padding:1px 6px;color:var(--muted);user-select:all}
.sf-mail{color:var(--muted);text-decoration:underline;text-underline-offset:2px}
.sf-mail:hover{color:var(--brand)}
@media (max-width:520px){
  .sitefoot{margin-top:22px;padding:18px 10px 20px}
  .sf-brand{font-size:12.5px;gap:7px}
  .sf-meta .sf-sep{display:none}
  .sf-meta{flex-direction:column;gap:3px}
}
@media print{.sitefoot{border-top:1px solid #999}.sf-link{background:none;color:#000;padding:0}}
CSS;
}

/**
 * One footer, rendered on both the sign-in screen and the dashboard.
 * Kept as a function so the two can never drift apart.
 *
 * $installationId is shown because it is the reference a client quotes when
 * reporting a problem: it identifies the install without exposing the path.
 */
function renderFooter(string $installationId = '', bool $compact = false): void
{
    $year = date('Y');
    ?>
    <footer class="sitefoot<?= $compact ? ' sitefoot-compact' : '' ?>">
      <div class="sf-brand">
        <svg class="sf-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>
        <span class="sf-co"><?= h(COMPANY_NAME) ?></span>
        <a class="sf-link" href="<?= h(COMPANY_URL) ?>" target="_blank" rel="noopener noreferrer">
          <?= h(COMPANY_URL_LABEL) ?>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 17 17 7M9 7h8v8"/></svg>
        </a>
      </div>

      <div class="sf-meta">
        <span><?= h(SHORT_NAME) ?> <b>v<?= h(APP_VERSION) ?></b></span>
        <span class="sf-sep" aria-hidden="true">&middot;</span>
        <span>&copy; <?= h($year) ?> <?= h(COMPANY_NAME) ?></span>
        <?php if (SUPPORT_EMAIL !== ''): ?>
          <span class="sf-sep" aria-hidden="true">&middot;</span>
          <span><a class="sf-mail" href="mailto:<?= h(SUPPORT_EMAIL) ?>"><?= h(SUPPORT_EMAIL) ?></a></span>
        <?php endif; ?>
      </div>

      <?php if (!$compact): ?>
        <div class="sf-meta sf-fine">
          <span>AMWScan (GPL-3.0) &middot; integrity verification vs WordPress.org</span>
          <?php if ($installationId !== ''): ?>
            <span class="sf-sep" aria-hidden="true">&middot;</span>
            <span>Install ref <code class="sf-id"><?= h($installationId) ?></code></span>
          <?php endif; ?>
        </div>
      <?php endif; ?>
    </footer>
    <?php
}

function findingPath(array $finding): string
{
    $abs = trim((string)($finding['absolute_path'] ?? ''));
    if ($abs !== '') return $abs;
    return (string)($finding['file'] ?? '');
}

function findingId(string $file): string
{
    return substr(hash('sha256', $file), 0, 16);
}
function quarantineFiles(string $quarantineDir): array
{
    $files = [];
    if (!is_dir($quarantineDir)) return $files;
    try {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($quarantineDir, FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $item) if ($item->isFile()) $files[] = slash($item->getPathname());
    } catch (Throwable) {}
    sort($files);
    return $files;
}
function quarantineRelative(string $stored, string $quarantineDir): string
{
    $base = rtrim(slash($quarantineDir), '/');
    $stored = slash($stored);
    if (!str_starts_with($stored, $base)) return '';
    return ltrim(substr($stored, strlen($base)), '/');
}
/**
 * Reconcile the manifest with what is actually on disk. Files AMWScan
 * quarantined by itself during a scan get picked up here.
 */
function syncQuarantine(string $quarantineDir, string $manifestFile, string $scanRoot): array
{
    $manifest = readJson($manifestFile);
    $entries = isset($manifest['entries']) && is_array($manifest['entries']) ? $manifest['entries'] : [];
    $byId = [];
    foreach ($entries as $entry) {
        if (is_array($entry) && !empty($entry['id']) && !empty($entry['relative'])) $byId[(string)$entry['id']] = $entry;
    }
    $changed = false;
    $seen = [];
    foreach (quarantineFiles($quarantineDir) as $stored) {
        $relative = quarantineRelative($stored, $quarantineDir);
        if ($relative === '') continue;
        $id = findingId($relative);
        $seen[$id] = true;
        if (!isset($byId[$id])) {
            $byId[$id] = [
                'id' => $id,
                'relative' => $relative,
                'original' => rtrim(slash($scanRoot), '/') . '/' . $relative,
                'source' => 'auto',
                'quarantined_at' => date(DATE_ATOM, (int)(@filemtime($stored) ?: time())),
                'size' => (int)@filesize($stored),
            ];
            $changed = true;
        } else {
            $byId[$id]['size'] = (int)@filesize($stored);
        }
    }
    foreach ($byId as $id => $entry) {
        if (empty($seen[$id])) { unset($byId[$id]); $changed = true; }
    }
    if ($changed) { try { writeJson($manifestFile, ['entries' => array_values($byId)]); } catch (Throwable) {} }
    return $byId;
}
function saveManifest(string $manifestFile, array $byId): void
{
    writeJson($manifestFile, ['entries' => array_values($byId)]);
}
function pruneEmptyDirs(string $directory): void
{
    if (!is_dir($directory)) return;
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isDir() && !(glob($item->getPathname() . '/*') ?: [])) @rmdir($item->getPathname());
        }
    } catch (Throwable) {}
}
/** Move one live file into quarantine and record it. */
function quarantineFile(string $file, string $scanRoot, string $quarantineDir, string $manifestFile): array
{
    $real = realpath($file);
    if ($real === false || !is_file($real)) throw new RuntimeException('File no longer exists: ' . $file);
    $real = slash($real);
    $rootNormal = rtrim(slash($scanRoot), '/');
    if ($real !== $rootNormal && !str_starts_with($real, $rootNormal . '/')) {
        throw new RuntimeException('File is outside the scan path: ' . $real);
    }
    $relative = ltrim(substr($real, strlen($rootNormal)), '/');
    if ($relative === '') throw new RuntimeException('Invalid file: ' . $real);

    $destination = rtrim(slash($quarantineDir), '/') . '/' . $relative;
    $destinationDir = dirname($destination);
    if (!is_dir($destinationDir) && !@mkdir($destinationDir, 0700, true) && !is_dir($destinationDir)) {
        throw new RuntimeException('Cannot create quarantine folder for ' . $relative);
    }
    if (file_exists($destination)) $destination .= '.' . date('YmdHis');
    if (!@rename($real, $destination)) {
        throw new RuntimeException('Unable to move ' . $real . ' (check folder write permissions)');
    }
    @chmod($destination, 0600);

    $storedRelative = quarantineRelative($destination, $quarantineDir);
    $entry = [
        'id' => findingId($storedRelative),
        'relative' => $storedRelative,
        'original' => $real,
        'source' => 'manual',
        'quarantined_at' => date(DATE_ATOM),
        'size' => (int)@filesize($destination),
    ];
    $manifest = syncQuarantine($quarantineDir, $manifestFile, $scanRoot);
    $manifest[$entry['id']] = $entry;
    saveManifest($manifestFile, $manifest);
    return $entry;
}
/** Put a quarantined file back where it came from. */
function restoreQuarantined(array $entry, string $quarantineDir, array $bases): void
{
    $stored = rtrim(slash($quarantineDir), '/') . '/' . (string)$entry['relative'];
    $realStored = realpath($stored);
    $realQuarantine = realpath($quarantineDir);
    if ($realStored === false || !is_file($realStored)) throw new RuntimeException('Quarantined file is missing: ' . (string)$entry['relative']);
    if ($realQuarantine === false || !str_starts_with(slash($realStored), rtrim(slash($realQuarantine), '/') . '/')) {
        throw new RuntimeException('Refusing to restore from outside the quarantine folder.');
    }
    $target = slash((string)($entry['original'] ?? ''));
    if ($target === '') throw new RuntimeException('No original location recorded.');
    if (!withinBases($target, $bases)) throw new RuntimeException('Original location is outside the allowed area: ' . $target);
    if (file_exists($target)) throw new RuntimeException('A file already exists at ' . $target);
    $targetDir = dirname($target);
    if (!is_dir($targetDir) && !@mkdir($targetDir, 0755, true) && !is_dir($targetDir)) {
        throw new RuntimeException('Cannot create folder ' . $targetDir);
    }
    if (!@rename($realStored, $target)) throw new RuntimeException('Unable to restore ' . $target . ' (check permissions)');
    @chmod($target, 0644);
}
function deleteQuarantined(array $entry, string $quarantineDir): void
{
    $stored = rtrim(slash($quarantineDir), '/') . '/' . (string)$entry['relative'];
    $realStored = realpath($stored);
    $realQuarantine = realpath($quarantineDir);
    if ($realStored === false || !is_file($realStored)) return;
    if ($realQuarantine === false || !str_starts_with(slash($realStored), rtrim(slash($realQuarantine), '/') . '/')) {
        throw new RuntimeException('Refusing to delete outside the quarantine folder.');
    }
    if (!@unlink($realStored)) throw new RuntimeException('Unable to delete ' . (string)$entry['relative']);
}

/* ------------------------------------------------------------------
 * Live progress / background execution
 * ------------------------------------------------------------------ */

/** A scan is running if the lock file cannot be acquired. */
function scanIsRunning(string $lockFile): bool
{
    if (!is_file($lockFile)) return false;
    $handle = @fopen($lockFile, 'c');
    if (!$handle) return false;
    $free = flock($handle, LOCK_EX | LOCK_NB);
    if ($free) flock($handle, LOCK_UN);
    fclose($handle);
    return !$free;
}
/** Read the tail of the in-progress log and return [percent, totalFiles]. */
function tailProgress(string $file): array
{
    clearstatcache(true, $file);
    if (!is_file($file)) return [0, 0];
    $handle = @fopen($file, 'rb');
    if (!$handle) return [0, 0];
    $size = (int)@filesize($file);
    if ($size > 16384) fseek($handle, -16384, SEEK_END);
    $chunk = (string)fread($handle, 16384);
    fclose($handle);
    $chunk = stripAnsi($chunk);
    if (!preg_match_all('/(\d+)\s*\/\s*(\d+)/', $chunk, $matches) || empty($matches[2])) return [0, 0];
    $last = count($matches[2]) - 1;
    $current = (int)$matches[1][$last];
    $total = (int)$matches[2][$last];
    if ($total <= 0) return [0, 0];
    return [min(100, (int)round($current / $total * 100)), $total];
}
/** Launch the scan detached, so the HTTP request returns straight away. */
function startBackgroundScan(array $paths, string $dataDir, string $phpCli): void
{
    if (scanIsRunning($paths['lock'])) throw new RuntimeException('Another scan is already running.');
    if (!is_file($paths['scanner'])) throw new RuntimeException('scanner.php must be beside security-scanner.php.');
    if (!execAllowed()) throw new RuntimeException('PHP exec() is disabled, so background scans are not possible. Turn off background mode in Scan Configuration.');
    if (!phpWorks($phpCli)) {
        throw new RuntimeException('No usable PHP command-line binary was found (tried: ' . (implode(', ', phpCandidates()) ?: 'none') . '). Turn off background mode in Scan Configuration, or ask your host for the PHP CLI path and set PHP_CLI_PATH at the top of this file.');
    }

    // Keep the child's output. Throwing it away is why a failed launch used to
    // be a mystery - the real error was going straight to /dev/null.
    $launchLog = $dataDir . DIRECTORY_SEPARATOR . 'launch.log';
    @unlink($launchLog);
    $statusBefore = @filemtime($paths['status']) ?: 0;

    $command = escapeshellarg($phpCli)
        . ' -d ' . escapeshellarg('memory_limit=' . DASHBOARD_MEMORY_LIMIT)
        . ' ' . escapeshellarg($paths['self']) . ' --scan'
        . ' --data=' . escapeshellarg($dataDir)
        . ' --path=' . escapeshellarg($paths['root']);
    $launch = ($paths['nohup'] ? 'nohup ' : '') . $command . ' >> ' . escapeshellarg($launchLog) . ' 2>&1 & echo $!';

    $output = []; $exitCode = 1;
    exec($launch, $output, $exitCode);

    // Confirm it really started. flock is not reliable on every shared host or
    // network filesystem, so accept any of three independent signals.
    for ($i = 0; $i < 40; $i++) {
        clearstatcache();
        if (scanIsRunning($paths['lock'])) return;
        $current = readJson($paths['status']);
        if ((string)($current['completion_status'] ?? '') === 'running') return;
        if ((@filemtime($paths['status']) ?: 0) > $statusBefore) return; // already finished
        usleep(200000);
    }

    $detail = is_file($launchLog) ? trim((string)@file_get_contents($launchLog)) : '';
    throw new RuntimeException(
        'The scan process did not start. '
        . ($detail !== ''
            ? 'The scan process reported: ' . substr($detail, 0, 600)
            : 'It produced no output at all, which usually means your host blocks detached background processes.')
        . ' Untick "Run scans in the background" in Scan Configuration to run them the old way, or use a cron job.'
    );
}

/**
 * Parse the scan log ONE LINE AT A TIME.
 *
 * The log carries roughly 200 bytes of progress output per scanned file, so a
 * 200,000-file site produces ~40 MB. Loading that into a string, splitting it
 * into an array of lines and running preg_match_all over the whole thing needs
 * several hundred MB and dies with "Allowed memory size exhausted". Streaming
 * keeps memory flat no matter how large the site is.
 */
function parseLogStream(string $file, array $exclusions, string $root): array
{
    $empty = ['files_scanned'=>0,'completed'=>false,'findings'=>[],'excluded_findings'=>[],'findings_truncated'=>false];
    $handle = @fopen($file, 'rb');
    if (!$handle) return $empty;

    $filesScanned = 0;
    $progressReachedEnd = false;
    $previous = [];   // the 2 lines before the current one
    $open = [];       // finding blocks still collecting trailing context
    $blocks = [];     // completed blocks
    $seenFindings = 0;
    $truncated = false;

    $handleLine = static function (string $line) use (
        &$filesScanned, &$progressReachedEnd, &$previous, &$open, &$blocks, &$seenFindings, &$truncated
    ): void {
        $line = stripAnsi($line);

        if (preg_match_all('/(\d+)\s*\/\s*(\d+)/', $line, $matches) && !empty($matches[2])) {
            foreach ($matches[2] as $i => $totalRaw) {
                $total = (int)$totalRaw;
                if ($total > $filesScanned) $filesScanned = $total;
                if ($total > 0 && (int)$matches[1][$i] >= $total) $progressReachedEnd = true;
            }
            unset($matches);
        }
        if (!$progressReachedEnd && str_contains($line, '100%')) $progressReachedEnd = true;

        foreach ($open as $key => $block) {
            $open[$key]['lines'][] = $line;
            if (--$open[$key]['remaining'] <= 0) {
                $blocks[] = implode(PHP_EOL, $open[$key]['lines']);
                unset($open[$key]);
            }
        }

        if (preg_match('/PROBABLE\s+MALWARE\s+FOUND|MALWARE\s+FOUND|INFECTED\s+FILE/i', $line) === 1) {
            $seenFindings++;
            if ($seenFindings <= MAX_FINDINGS_STORED * 2) {
                $start = $previous;
                $start[] = $line;
                $open[] = ['lines'=>$start, 'remaining'=>18 - count($start)];
            } else {
                $truncated = true;
            }
        }

        $previous[] = $line;
        if (count($previous) > 2) array_shift($previous);
    };

    // Read in fixed chunks and split on any line ending. AMWScan's progress
    // bar sometimes uses a bare carriage return, which fgets() does NOT treat
    // as a line break - that would hand us a multi-megabyte "line" and undo
    // the whole point of streaming. A hard cap keeps one line bounded even if
    // the log contains no line breaks at all.
    $buffer = '';
    while (!feof($handle)) {
        $chunk = fread($handle, 65536);
        if ($chunk === false || $chunk === '') break;
        $buffer .= $chunk;
        $pieces = preg_split('/\R/', $buffer) ?: [];
        $buffer = (string)array_pop($pieces);
        foreach ($pieces as $piece) $handleLine($piece);
        unset($pieces);
        if (strlen($buffer) > 262144) { $handleLine($buffer); $buffer = ''; }
    }
    if ($buffer !== '') $handleLine($buffer);
    foreach ($open as $block) $blocks[] = implode(PHP_EOL, $block['lines']);
    fclose($handle);

    $unique = [];
    foreach ($blocks as $block) {
        $block = trim($block);
        if (strlen($block) > MAX_FINDING_DETAIL) $block = substr($block, 0, MAX_FINDING_DETAIL) . PHP_EOL . '... (details truncated)';
        $path = '';
        if (preg_match('~(/[^\s<>"\']+\.(?:php|phtml|inc))~i', $block, $pathMatch)) $path = $pathMatch[1];
        $trigger = 'Signature or pattern match';
        if (preg_match('/Potentially dangerous function\s+[`\'\"]?([a-zA-Z0-9_]+)/i', $block, $triggerMatch)) {
            $trigger = $triggerMatch[1] . '()';
        }
        $key = $path !== '' ? $path : hash('sha256', $block);
        $unique[$key] = [
            'file' => $path ?: 'Path not parsed',
            'classification' => 'Probable malware',
            'trigger' => $trigger,
            'action' => 'Review required',
            'details' => $block,
        ];
    }
    unset($blocks);

    $active = [];
    $excluded = [];
    foreach ($unique as $finding) {
        $matched = false;
        if ($finding['file'] !== 'Path not parsed') {
            foreach ($exclusions as $rule) {
                if (exclusionMatches($finding['file'], $rule, $root)) { $matched = true; break; }
            }
        }
        if ($matched) $excluded[] = $finding; else $active[] = $finding;
    }
    if (count($active) > MAX_FINDINGS_STORED) { $active = array_slice($active, 0, MAX_FINDINGS_STORED); $truncated = true; }
    if (count($excluded) > MAX_FINDINGS_STORED) $excluded = array_slice($excluded, 0, MAX_FINDINGS_STORED);

    $completed = $progressReachedEnd || ($filesScanned > 0 && count($unique) > 0);
    return [
        'files_scanned' => $filesScanned,
        'completed' => $completed,
        'findings' => $active,
        'excluded_findings' => $excluded,
        'findings_truncated' => $truncated,
    ];
}
function reportFiles(string $reportsDir): array
{
    $files = glob($reportsDir . DIRECTORY_SEPARATOR . 'scan_*.json') ?: [];
    rsort($files, SORT_STRING);
    return $files;
}
function pruneReports(string $reportsDir): void
{
    $cutoff = time() - REPORT_RETENTION_DAYS * 86400;
    foreach (glob($reportsDir . DIRECTORY_SEPARATOR . 'scan_*.*') ?: [] as $file) {
        $time = @filemtime($file);
        if (is_int($time) && $time < $cutoff) @unlink($file);
    }
}

/**
 * Rank a finding by how close it is to live remote control of the site.
 * Reads the fields the engines actually produce: AMWScan writes
 * 'classification'/'trigger', the signature engine writes 'threat'/'type'.
 */
function findingSeverity(array $finding): string
{
    // Integrity and structural findings state their own severity, because it
    // is a fact about the file (a modified core file is critical, full stop),
    // not something to be inferred from the text of a signature name.
    $explicit = strtolower(trim((string)($finding['severity'] ?? '')));
    if (in_array($explicit, ['critical', 'high', 'medium', 'low'], true)) return $explicit;

    // AMWScan reports a fixed classification ("Probable malware") plus the
    // construct that tripped it ("eval()", "base64_decode", a filename...).
    // Only the trigger carries information, so only the trigger is graded -
    // feeding the constant in as well pushed every finding to one grade.
    $trigger = strtolower(trim((string)($finding['trigger'] ?? '')));

    if ($trigger !== '' && $trigger !== 'pattern match') {
        // Direct execution of attacker-supplied input.
        foreach (['shell_exec', 'passthru', 'proc_open', 'popen', 'pcntl_exec',
                  'shell', 'backdoor', 'system(', 'system'] as $needle) {
            if (str_contains($trigger, $needle)) return 'critical';
        }
        // Code execution, but usually needing a second stage or a trigger.
        foreach (['eval', 'assert', 'create_function', 'preg_replace',
                  'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13',
                  'exec'] as $needle) {
            if (str_contains($trigger, $needle)) return 'high';
        }
        // Worth a human look; legitimate plugins do these too.
        foreach (['include', 'require', 'file_put_contents', 'fwrite', 'fopen',
                  'curl', 'chmod', 'unlink', 'move_uploaded_file'] as $needle) {
            if (str_contains($trigger, $needle)) return 'medium';
        }
    }

    // AMWScan flagged the file but the trigger was not parsed from the log.
    // It still deserves review - it just cannot be ranked confidently.
    $generic = strtolower((string)($finding['classification'] ?? ''));
    if (str_contains($generic, 'malware') || str_contains($generic, 'probable')) {
        return 'medium';
    }
    return 'low';
}

/** Windows uses NUL, everything else /dev/null. */
function nullDevice(): string
{
    return isWindows() ? 'NUL' : '/dev/null';
}
function isWindows(): bool
{
    return DIRECTORY_SEPARATOR === '\\';
}

/**
 * Return a PHP CLI binary that actually runs, or '' if there is none.
 * Tries the configured/cached path first, then probes every known layout
 * (XAMPP, WAMP, Laragon, cPanel, Plesk, CloudLinux, LiteSpeed, plain Linux).
 * The winner is cached in config.json so the probe runs once, not every scan.
 */
function resolveWorkingPhp(string $preferred, string $configFile = ''): string
{
    if ($preferred !== '' && phpWorks($preferred)) return $preferred;
    foreach (phpCandidates() as $candidate) {
        if ($candidate === $preferred) continue;
        if (!phpWorks($candidate)) continue;
        if ($configFile !== '') {
            try {
                $config = readJson($configFile);
                $config['php_cli'] = $candidate;
                writeJson($configFile, $config);
            } catch (Throwable) {}
        }
        return $candidate;
    }
    return '';
}

/* ---- cooperative cancel ---------------------------------------------- */
function cancelFlagFile(string $dataDir): string
{
    return rtrim($dataDir, '/\\') . DIRECTORY_SEPARATOR . 'cancel.flag';
}
function requestCancel(string $dataDir): void
{
    @file_put_contents(cancelFlagFile($dataDir), (string)time());
}
function cancelRequested(string $dataDir): bool
{
    return is_file(cancelFlagFile($dataDir));
}
function clearCancel(string $dataDir): void
{
    @unlink(cancelFlagFile($dataDir));
}

/* ===================================================================
 * Layer 1 - Integrity verification
 * ===================================================================
 * Deterministic. Compares files against known-good hashes instead of
 * guessing whether code "looks dangerous". Two independent sources:
 *
 *   A. WordPress.org official checksums for core (needs network on the
 *      scanned server, which is where this runs).
 *   B. A locally captured baseline of the whole tree (needs nothing,
 *      and covers plugins and themes that WordPress.org cannot vouch for).
 * =================================================================== */

const CORE_DIRS = ['wp-admin', 'wp-includes'];

/** Locate the WordPress root at, above, or one level below the scan path. */
function findWpRoot(string $scanPath): ?string
{
    $path = rtrim(str_replace('\\', '/', $scanPath), '/');
    for ($i = 0; $i < 4 && $path !== '' && $path !== '/'; $i++) {
        if (is_file($path . '/wp-includes/version.php')) return $path;
        $parent = dirname($path);
        if ($parent === $path) break;
        $path = $parent;
    }
    foreach ((glob(rtrim(str_replace('\\','/',$scanPath), '/') . '/*/wp-includes/version.php') ?: []) as $hit) {
        return dirname(dirname($hit));
    }
    return null;
}

/** Read $wp_version without executing the file. */
function wpVersion(string $wpRoot): ?string
{
    $file = $wpRoot . '/wp-includes/version.php';
    $src  = @file_get_contents($file, false, null, 0, 65536);
    if (!is_string($src)) return null;
    if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $src, $m) !== 1) return null;
    return $m[1];
}

/**
 * Official core checksums, cached on disk.
 * The API returns MD5 today; hash length is detected per entry so a future
 * switch to SHA-256 keeps working without a code change.
 */
function coreChecksums(string $version, string $cacheDir, string $locale = 'en_US'): array
{
    $safe  = preg_replace('/[^0-9A-Za-z._-]/', '', $version . '-' . $locale);
    $cache = rtrim($cacheDir, '/\\') . DIRECTORY_SEPARATOR . 'checksums-' . $safe . '.json';

    if (is_file($cache) && (time() - (int)@filemtime($cache)) < 2592000) {
        $data = json_decode((string)@file_get_contents($cache), true);
        if (is_array($data) && $data) return ['ok' => true, 'source' => 'cache', 'checksums' => $data];
    }

    $url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($version)
         . '&locale=' . rawurlencode($locale);
    $raw = fetchUrl($url);
    if ($raw === null) {
        return ['ok' => false, 'source' => 'unreachable', 'checksums' => [],
                'error' => 'Could not reach api.wordpress.org to fetch official checksums.'];
    }
    $json = json_decode($raw, true);
    $sums = (is_array($json) && isset($json['checksums']) && is_array($json['checksums']))
        ? $json['checksums'] : null;
    if (!$sums) {
        return ['ok' => false, 'source' => 'bad-response', 'checksums' => [],
                'error' => 'api.wordpress.org did not return checksums for version ' . $version . '.'];
    }
    @file_put_contents($cache, json_encode($sums));
    @chmod($cache, 0600);
    return ['ok' => true, 'source' => 'wordpress.org', 'checksums' => $sums];
}

/** Fetch a URL with curl, falling back to streams. Null on any failure. */
function fetchUrl(string $url): ?string
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 20,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_USERAGENT      => 'GTS-Malware-Scanner',
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if (is_string($body) && $code === 200 && $body !== '') return $body;
        return null;
    }
    if (!ini_get('allow_url_fopen')) return null;
    $ctx  = stream_context_create(['http' => ['timeout' => 20, 'user_agent' => 'GTS-Malware-Scanner']]);
    $body = @file_get_contents($url, false, $ctx);
    return is_string($body) && $body !== '' ? $body : null;
}

/** Hash a file with the algorithm implied by the expected digest length. */
function hashLike(string $file, string $expected): ?string
{
    $algo = strlen($expected) === 64 ? 'sha256' : 'md5';
    $h = @hash_file($algo, $file);
    return is_string($h) ? $h : null;
}

/**
 * Compare core against official checksums.
 * Three outcomes, all factual - no heuristics are involved at any point.
 */
function verifyCore(string $wpRoot, array $checksums): array
{
    $findings = ['modified' => [], 'unknown' => [], 'missing' => [], 'verified' => 0];
    $root = rtrim(str_replace('\\', '/', $wpRoot), '/');

    foreach ($checksums as $rel => $expected) {
        $rel = ltrim(str_replace('\\', '/', (string)$rel), '/');
        // wp-content is user territory; WordPress.org only vouches for what it ships.
        if (str_starts_with($rel, 'wp-content/')) continue;
        $abs = $root . '/' . $rel;
        if (!is_file($abs)) { $findings['missing'][] = $rel; continue; }
        $actual = hashLike($abs, (string)$expected);
        if ($actual === null) continue;
        if (!hash_equals(strtolower((string)$expected), strtolower($actual))) {
            $findings['modified'][] = $rel;
        } else {
            $findings['verified']++;
        }
    }

    // Anything executable sitting inside a core directory that WordPress does
    // not ship. This is where dropped shells live.
    $known = [];
    foreach ($checksums as $rel => $_) $known[ltrim(str_replace('\\','/',(string)$rel), '/')] = true;
    foreach (CORE_DIRS as $dir) {
        $base = $root . '/' . $dir;
        if (!is_dir($base)) continue;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);
        foreach ($it as $fi) {
            $abs = $fi->getRealPath();
            if ($abs === false || !is_file($abs)) continue;
            if (!preg_match('/\.(php|phtml|phar|inc|js)$/i', $abs)) continue;
            $rel = ltrim(substr(str_replace('\\','/',$abs), strlen($root)), '/');
            if (!isset($known[$rel])) $findings['unknown'][] = $rel;
        }
    }
    return $findings;
}

/* ---- Baseline: covers plugins and themes, and needs no network ---- */

/** Hash every scannable file under $root into a portable manifest. */
function captureBaseline(string $root, array $skipAbs = []): array
{
    $root = rtrim(str_replace('\\', '/', $root), '/');
    $skip = [];
    foreach ($skipAbs as $s) {
        $r = @realpath($s);
        if ($r !== false) $skip[] = rtrim(str_replace('\\','/',$r), '/');
    }
    $map = [];
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);
    foreach ($it as $fi) {
        $abs = $fi->getRealPath();
        if ($abs === false || !is_file($abs)) continue;
        $n = str_replace('\\', '/', $abs);
        foreach ($skip as $s) { if ($n === $s || str_starts_with($n, $s . '/')) continue 2; }
        if (!preg_match('/\.(php|phtml|phar|inc|js|css|html?|htaccess)$|(^|\/)\.htaccess$/i', $n)) continue;
        $h = @hash_file('sha256', $abs);
        if ($h === false) continue;
        $map[ltrim(substr($n, strlen($root)), '/')] = $h;
    }
    return $map;
}

/** What changed since the baseline was captured. */
function baselineDrift(string $root, array $baseline, array $skipAbs = []): array
{
    $now  = captureBaseline($root, $skipAbs);
    $out  = ['added' => [], 'modified' => [], 'removed' => [], 'unchanged' => 0];
    foreach ($now as $rel => $hash) {
        if (!isset($baseline[$rel]))            $out['added'][] = $rel;
        elseif (!hash_equals($baseline[$rel], $hash)) $out['modified'][] = $rel;
        else                                    $out['unchanged']++;
    }
    foreach ($baseline as $rel => $_) if (!isset($now[$rel])) $out['removed'][] = $rel;
    return $out;
}

/* ===================================================================
 * Layer 2 - Structural rules. Also deterministic: these describe where
 * a file is and what it contains, not whether its code looks scary.
 * =================================================================== */
/**
 * Structural rules. These describe WHERE a file lives and WHAT it contains,
 * never whether its code "looks dangerous", so they apply to any PHP project -
 * WordPress, Laravel, Magento, or something hand-rolled.
 */
function structuralScan(string $root, bool $isWordPress = false): array
{
    $out  = [];
    $root = rtrim(str_replace('\\', '/', $root), '/');
    if (!is_dir($root)) return $out;

    // Directory names that hold user-supplied files on essentially every stack.
    // Deliberately narrow: "media", "files" and "assets" are too often ordinary
    // source directories to be worth the false positives.
    $uploadDirs = '(?:uploads?|attachments|userfiles|user-uploads|user_uploads)';

    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);

    foreach ($it as $fi) {
        $abs = $fi->getRealPath();
        if ($abs === false || !is_file($abs)) continue;
        $n = str_replace('\\', '/', $abs);

        // Executable PHP sitting in a directory meant for user uploads.
        if (preg_match('#/' . $uploadDirs . '/#i', $n)
            && preg_match('/\.(php|phtml|phar|php[0-9]|inc)$/i', $n)) {
            $out[] = ['file' => $abs, 'threat' => 'PHP file inside an upload directory', 'severity' => 'critical'];
            continue;
        }

        // A PHP open tag inside a file that claims to be an image or document.
        // Anywhere in the tree - this is how a shell gets past an upload filter.
        if (preg_match('/\.(jpe?g|png|gif|webp|bmp|ico|svg|pdf|zip|txt|log|csv)$/i', $n)
            && (int)@filesize($abs) <= 4194304) {
            $head = @file_get_contents($abs, false, null, 0, 8192);
            if (is_string($head) && preg_match('/<\?php\b/i', $head)) {
                $out[] = ['file' => $abs, 'threat' => 'PHP code inside a non-PHP file', 'severity' => 'critical'];
            }
        }
    }

    // WordPress-specific: mu-plugins load on every request and cannot be
    // disabled from wp-admin, so they are a favourite persistence spot.
    if ($isWordPress) {
        foreach ((glob($root . '/wp-content/mu-plugins/*.php') ?: []) as $f) {
            $out[] = ['file' => $f, 'threat' => 'Must-use plugin (loads on every request, cannot be disabled from wp-admin)', 'severity' => 'medium'];
        }
    }
    return $out;
}


/** Shape an integrity result like the rest of the finding pipeline. */
function integrityFinding(string $wpRoot, string $rel, string $threat, string $severity, string $source): array
{
    $abs = rtrim(str_replace('\\', '/', $wpRoot), '/') . '/' . ltrim($rel, '/');
    return [
        'file'           => $abs,
        'classification' => $source,
        'trigger'        => '',
        'threat'         => $threat,
        'severity'       => $severity,
        'source'         => $source,
        'details'        => $threat . "\n" . $abs,
        'absolute_path'  => $abs,
    ];
}

/** Collapse duplicates from several integrity layers into one row per file. */
function mergeIntegrityFindings(array $items): array
{
    $rank = ['critical' => 3, 'high' => 2, 'medium' => 1, 'low' => 0];
    $by = [];
    foreach ($items as $it) {
        $k = $it['absolute_path'] ?? $it['file'];
        if (!isset($by[$k])) { $by[$k] = $it; $by[$k]['sources'] = [$it['source']]; continue; }
        if (!in_array($it['source'], $by[$k]['sources'], true)) $by[$k]['sources'][] = $it['source'];
        if (($rank[$it['severity']] ?? 0) > ($rank[$by[$k]['severity']] ?? 0)) {
            $by[$k]['severity'] = $it['severity'];
            $by[$k]['threat']   = $it['threat'];
        }
    }
    return array_values($by);
}

/** Merge AMWScan findings with integrity findings, one row per file. */
function mergeAllFindings(array $amwscan, array $integrity): array
{
    $by = [];
    foreach ($amwscan as $f) {
        $k = findingPath($f);
        $f['sources'] = ['AMWScan'];
        $by[$k] = $f;
    }
    foreach ($integrity as $f) {
        $k = findingPath($f);
        if (!isset($by[$k])) { $by[$k] = $f; continue; }
        $by[$k]['sources'] = array_values(array_unique(array_merge($by[$k]['sources'] ?? [], $f['sources'] ?? [$f['source']])));
        if (empty($by[$k]['threat'])) $by[$k]['threat'] = $f['threat'];
        if (!empty($f['severity'])) $by[$k]['severity'] = $f['severity'];
        if (empty($by[$k]['absolute_path']) && !empty($f['absolute_path'])) $by[$k]['absolute_path'] = $f['absolute_path'];
    }
    return array_values($by);
}

function runScan(array $paths): array
{
    if (!is_file($paths['scanner'])) throw new RuntimeException('scanner.php must be beside security-scanner.php.');
    if (!is_dir($paths['root'])) throw new RuntimeException('Scan path is not a directory: ' . $paths['root']);
    if (!execAllowed()) throw new RuntimeException('PHP exec() is disabled.');

    $lock = @fopen($paths['lock'], 'c');
    if (!$lock) throw new RuntimeException('Unable to create scan lock.');
    if (!flock($lock, LOCK_EX | LOCK_NB)) { fclose($lock); throw new RuntimeException('Another scan is already running.'); }

    try {
        $reportId = date('Y-m-d_H-i-s');
        $started = time();
        $textReport = $paths['reports'] . '/scan_' . $reportId . '.txt';
        $jsonReport = $paths['reports'] . '/scan_' . $reportId . '.json';
        writeJson($paths['status'], [
            'completion_status'=>'running','security_result'=>'pending',
            'started_at'=>date(DATE_ATOM),'scan_path'=>$paths['root'],
            'raw_log'=>basename($textReport),'pid'=>getmypid(),
        ]);

        $rules = readExclusions($paths['exclusions']);
        $ignored = [$paths['scanner'], $paths['self'], $paths['data']];
        foreach ($rules as $rule) $ignored[] = normalizePath($rule, $paths['root']);

        clearCancel($paths['data']);

        // Resolve a PHP CLI that actually runs. This probes XAMPP / WAMP /
        // Laragon / cPanel / Plesk layouts and caches the winner in config.json.
        $phpBinary = resolveWorkingPhp((string)($paths['php_cli'] ?? ''), (string)($paths['config'] ?? ''));

        // ---- Layer 1 + 2 run in-process and need no PHP CLI ----------
        $wpRoot     = findWpRoot($paths['root']);
        $wpVer      = $wpRoot ? wpVersion($wpRoot) : null;
        $layer      = ['core' => null, 'baseline' => null, 'structural' => 0];
        $extra      = [];

        // The tree to verify: the WordPress root when there is one, otherwise
        // whatever was asked to be scanned. Baseline drift and the structural
        // rules are plain file inspection, so they work on any PHP project.
        $verifyRoot = $wpRoot ?? rtrim(str_replace('\\', '/', $paths['root']), '/');
        $isWp = $wpRoot !== null;

        // 1a. Official core checksums. WordPress only - nobody publishes
        //     authoritative hashes for an arbitrary PHP application.
        if ($isWp && $wpVer !== null) {
            $sums = coreChecksums($wpVer, $paths['data']);
            if (!empty($sums['ok'])) {
                $core = verifyCore($wpRoot, $sums['checksums']);
                $layer['core'] = [
                    'source' => $sums['source'], 'version' => $wpVer,
                    'verified' => $core['verified'],
                    'modified' => count($core['modified']),
                    'unknown'  => count($core['unknown']),
                    'missing'  => count($core['missing']),
                ];
                foreach ($core['modified'] as $rel) $extra[] = integrityFinding($wpRoot, $rel,
                    'Core file modified - does not match WordPress ' . $wpVer, 'critical', 'Core integrity');
                foreach ($core['unknown'] as $rel)  $extra[] = integrityFinding($wpRoot, $rel,
                    'Unknown file inside a WordPress core directory', 'critical', 'Core integrity');
                foreach ($core['missing'] as $rel)  $extra[] = integrityFinding($wpRoot, $rel,
                    'Core file missing from this install', 'medium', 'Core integrity');
            } else {
                $layer['core'] = ['source' => $sums['source'], 'version' => $wpVer,
                                  'error' => $sums['error'] ?? 'unavailable'];
            }
        }

        // 1b. Baseline drift. Pure hashing - applies to ANY codebase, and is
        //     the only layer that can vouch for third-party plugins, themes,
        //     vendor directories or hand-written application code.
        $baseFile = $paths['data'] . DIRECTORY_SEPARATOR . 'baseline.json';
        if (is_file($baseFile)) {
            $base = json_decode((string)@file_get_contents($baseFile), true);
            if (is_array($base) && $base) {
                $drift = baselineDrift($verifyRoot, $base, [$paths['data'], $paths['self'], $paths['scanner']]);
                $layer['baseline'] = [
                    'captured_at' => date(DATE_ATOM, (int)@filemtime($baseFile)),
                    'unchanged' => $drift['unchanged'],
                    'added' => count($drift['added']),
                    'modified' => count($drift['modified']),
                    'removed' => count($drift['removed']),
                ];
                foreach ($drift['added'] as $rel) $extra[] = integrityFinding($verifyRoot, $rel,
                    'New file since the baseline was captured', 'high', 'Baseline drift');
                foreach ($drift['modified'] as $rel) $extra[] = integrityFinding($verifyRoot, $rel,
                    'File changed since the baseline was captured', 'high', 'Baseline drift');
            }
        }

        // 2. Structural rules. Any codebase.
        foreach (structuralScan($verifyRoot, $isWp) as $hit) {
            $layer['structural']++;
            $extra[] = [
                'file' => $hit['file'],
                'classification' => 'Structural',
                'trigger' => '',
                'threat' => $hit['threat'],
                'severity' => $hit['severity'],
                'source' => 'Structural',
                'details' => $hit['threat'] . "\n" . $hit['file'],
                'absolute_path' => $hit['file'],
            ];
        }

        // Deduplicate: one file reported by several layers becomes one finding.
        $extra = mergeIntegrityFindings($extra);

        // ---- AMWScan needs PHP CLI. Without it the malware scan cannot run,
        // but the integrity layers above already examined the tree, so this is
        // a partial result rather than a total failure. It must never be
        // presented as "clean".
        $amwscanRan = false;
        $parsed = ['findings'=>[], 'excluded_findings'=>[], 'files_scanned'=>0, 'completed'=>false];
        $exitCode = 0;
        $cliError = '';

        if ($phpBinary === '') {
            $tried = phpCandidates();
            $cliError = 'No working PHP command-line binary was found, so the AMWScan malware scan did not run. '
                . ($tried ? 'Tried: ' . implode(', ', array_slice($tried, 0, 6)) . '. ' : 'No candidate paths existed on this server. ')
                . 'Set PHP_CLI_PATH at the top of this file (XAMPP: C:\\xampp\\php\\php.exe, cPanel: /usr/local/bin/php), or ask your host to enable PHP CLI.';
            if (!is_dir($verifyRoot)) {
                throw new RuntimeException($cliError . ' The scan path is not readable either, so nothing has been checked.');
            }
        } else {
            // AMWScan takes the scan path as the FIRST POSITIONAL argument.
            // There is no -p / -l flag: an unknown flag makes its parser abort
            // and silently drop every other option.
            $command = escapeshellarg($phpBinary)
                . ' -d ' . escapeshellarg('memory_limit=' . SCANNER_MEMORY_LIMIT)
                . ' -d ' . escapeshellarg('max_execution_time=0')
                . ' ' . escapeshellarg($paths['scanner'])
                . ' ' . escapeshellarg($paths['root'])
                . ' ' . (!empty($paths['auto_quarantine']) ? '--auto-quarantine' : '--auto-skip')
                . ' --disable-colors'
                . (DISABLE_CHECKSUM ? ' --disable-checksum' : '')
                . ' --ignore-paths ' . escapeshellarg(implode(',', array_unique($ignored)))
                . ' --path-quarantine ' . escapeshellarg($paths['quarantine'])
                . ' > ' . escapeshellarg($textReport) . ' 2>&1';

            $output = [];
            $exitCode = 1;
            exec($command, $output, $exitCode);
            @chmod($textReport, 0600);

            // Streamed from disk - the log is never loaded into memory as a whole.
            $parsed = parseLogStream($textReport, $rules, $paths['root']);
            $amwscanRan = true;
        }

        $cancelled = cancelRequested($paths['data']);

        // AMWScan findings first, then integrity/structural, deduplicated by path.
        $findings = mergeAllFindings($parsed['findings'], $extra);
        $quarantined = syncQuarantine($paths['quarantine'], $paths['manifest'], $paths['root']);
        $finished = time();

        $engines = [];
        if ($amwscanRan && !empty($parsed['completed'])) $engines[] = 'AMWScan';
        if ($layer['core'] !== null && isset($layer['core']['verified'])) $engines[] = 'Core integrity';
        if ($layer['baseline'] !== null) $engines[] = 'Baseline drift';
        $engines[] = 'Structural';

        // Outcome. "completed" requires that the malware scan actually ran and
        // finished. If only the integrity layers ran, this is explicitly
        // partial - the tree was verified but not scanned for malware.
        $amwscanOk = $amwscanRan && !empty($parsed['completed']);
        if ($cancelled)                     $completion = 'cancelled';
        elseif ($amwscanOk)                 $completion = 'completed';
        elseif ($engines !== [])            $completion = 'partial';
        else                                $completion = 'failed';

        $result = $completion === 'failed'
            ? 'unavailable'
            : (count($findings) > 0 ? 'findings' : 'clean');

        $notRun = [];
        if (!$amwscanOk) $notRun[] = 'AMWScan malware scan';
        if ($wpRoot === null) $notRun[] = 'WordPress core checksum verification (not a WordPress install)';
        elseif ($layer['core'] === null || !isset($layer['core']['verified'])) $notRun[] = 'core checksum verification';
        if ($layer['baseline'] === null) $notRun[] = 'baseline drift (no baseline captured yet)';

        $report = [
            'report_id'=>$reportId,
            'completion_status'=>$completion,
            'security_result'=>$result,
            'started_at'=>date(DATE_ATOM, $started),
            'finished_at'=>date(DATE_ATOM, $finished),
            'duration_seconds'=>$finished - $started,
            'scan_path'=>$paths['root'],
            'auto_quarantine'=>!empty($paths['auto_quarantine']),
            'files_scanned'=>(int)($parsed['files_scanned'] ?? 0),
            'findings_count'=>count($findings),
            'excluded_count'=>count($parsed['excluded_findings']),
            'quarantined_count'=>count($quarantined),
            'findings_truncated'=>!empty($parsed['findings_truncated']),
            'peak_memory'=>humanSize(memory_get_peak_usage(true)),
            'exit_code'=>$exitCode,
            'raw_log'=>basename($textReport),
            'findings'=>$findings,
            'excluded_findings'=>$parsed['excluded_findings'],
            'detection_engines'=>$engines,
            'not_run'=>$notRun,
            'php_binary'=>$phpBinary,
            'cli_error'=>$cliError,
            'cancelled'=>$cancelled,
            'wp_root'=>$wpRoot,
            'wp_version'=>$wpVer,
            'layers'=>$layer,
        ];
        writeJson($jsonReport, $report);
        writeJson($paths['status'], $report);
        pruneReports($paths['reports']);
        return $report;
    } catch (Throwable $error) {
        // Never leave status.json saying "running" after the run has died -
        // the dashboard would show a scan in progress that no longer exists.
        // Record why it stopped, and do not imply anything about the site.
        writeJson($paths['status'], [
            'completion_status' => 'failed',
            'security_result'   => 'unavailable',
            'started_at'        => date(DATE_ATOM, $started ?? time()),
            'finished_at'       => date(DATE_ATOM),
            'scan_path'         => $paths['root'],
            'findings'          => [],
            'findings_count'    => 0,
            'files_scanned'     => 0,
            'error_message'     => $error->getMessage(),
            'raw_log'           => isset($textReport) ? basename($textReport) : '',
        ]);
        throw $error;
    } finally {
        clearCancel($paths['data']);
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

try {
    ensureDir($dataDir); ensureDir($reportsDir); ensureDir($quarantineDir);
    if (!is_file($exclusionsFile)) saveExclusions($exclusionsFile, []);
} catch (Throwable $error) {
    http_response_code(500); exit('Initialization failed: ' . h($error->getMessage()));
}

$config = readJson($configFile);
$allowedBases = allowedBases($root);
$configuredScanPath = trim((string)($config['scan_path'] ?? ''));
$scanPathWarning = '';
$scanRoot = $root;
if ($configuredScanPath !== '') {
    $error = null;
    $resolved = resolveScanPath($configuredScanPath, $allowedBases, $error, false);
    if ($resolved !== null) {
        $scanRoot = $resolved;
    } else {
        $scanPathWarning = 'Saved scan path is unusable, falling back to the scanner folder. ' . (string)$error;
    }
}
$autoQuarantine = array_key_exists('auto_quarantine', $config) ? (bool)$config['auto_quarantine'] : AUTO_QUARANTINE;
$backgroundScan = array_key_exists('background_scan', $config) ? (bool)$config['background_scan'] : BACKGROUND_SCAN;
$phpCli = (string)($config['php_cli'] ?? '');

$paths = [
    'root'=>$scanRoot,'scanner'=>$scanner,'self'=>$self,'data'=>$dataDir,
    'reports'=>$reportsDir,'quarantine'=>$quarantineDir,'status'=>$statusFile,
    'manifest'=>$manifestFile,'exclusions'=>$exclusionsFile,'lock'=>$lockFile,
    'nohup'=>hasCommand('nohup'),'auto_quarantine'=>$autoQuarantine,
    'php_cli'=>$phpCli,'config'=>$configFile,
];

if (PHP_SAPI === 'cli') {
    $args = $argv ?? [];
    if (!in_array('--scan', $args, true)) {
        echo "Usage: php security-scanner.php --scan [--path=/absolute/path] [--data=/data/dir]\n";
        echo "Default scan path: " . $scanRoot . "\n";
        echo "Auto-quarantine: " . ($autoQuarantine ? 'on' : 'off') . "\n";
        exit(0);
    }
    foreach ($args as $arg) {
        if (!str_starts_with((string)$arg, '--path=')) continue;
        $error = null;
        $override = resolveScanPath(substr((string)$arg, 7), $allowedBases, $error, false);
        if ($override === null) { fwrite(STDERR, 'Invalid --path: ' . (string)$error . PHP_EOL); exit(1); }
        $paths['root'] = $scanRoot = $override;
    }
    try {
        $report = runScan($paths);
        echo 'Path: ' . $report['scan_path'] . PHP_EOL;
        echo 'Completion: ' . $report['completion_status'] . PHP_EOL;
        echo 'Result: ' . $report['security_result'] . PHP_EOL;
        echo 'Files: ' . $report['files_scanned'] . PHP_EOL;
        echo 'Findings: ' . $report['findings_count'] . PHP_EOL;
        echo 'Quarantined: ' . $report['quarantined_count'] . PHP_EOL;
        exit($report['completion_status'] === 'completed' ? 0 : 1);
    } catch (Throwable $error) {
        fwrite(STDERR, 'Scan failed: ' . $error->getMessage() . PHP_EOL); exit(1);
    }
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex,nofollow,noarchive');
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
session_name('gts_malware_scanner');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>$isHttps,'httponly'=>true,'samesite'=>'Strict']);
session_start();
if (isset($_SESSION['last']) && time() - (int)$_SESSION['last'] > SESSION_TIMEOUT) { $_SESSION=[]; session_regenerate_id(true); }
$_SESSION['last'] = time();
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
$csrf = (string)$_SESSION['csrf'];
$configured = !empty($config['password_hash']);
$authenticated = ($_SESSION['authenticated'] ?? false) === true;
$message = ''; $messageClass = '';
$selfUrl = strtok((string)$_SERVER['REQUEST_URI'], '?');
function csrfValid(string $token): bool { return isset($_SESSION['csrf']) && hash_equals((string)$_SESSION['csrf'], $token); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'setup' && !$configured) {
        $password=(string)($_POST['password']??''); $confirm=(string)($_POST['confirm']??'');
        if (strlen($password)<12) {$message='Use at least 12 characters.';$messageClass='error';}
        elseif ($password!==$confirm) {$message='Passwords do not match.';$messageClass='error';}
        else { writeJson($configFile,['password_hash'=>password_hash($password,PASSWORD_DEFAULT),'created_at'=>date(DATE_ATOM)]); session_regenerate_id(true); $_SESSION['authenticated']=true; header('Location: '.$selfUrl); exit; }
    } elseif ($action === 'login' && $configured) {
        if (password_verify((string)($_POST['password']??''),(string)$config['password_hash'])) { session_regenerate_id(true); $_SESSION['authenticated']=true; $_SESSION['csrf']=bin2hex(random_bytes(32)); header('Location: '.$selfUrl); exit; }
        usleep(400000); $message='Invalid password.'; $messageClass='error';
    } elseif ($authenticated) {
        if (!csrfValid((string)($_POST['csrf']??''))) { http_response_code(403); exit('Invalid security token.'); }
        if ($action==='logout') { $_SESSION=[]; session_destroy(); header('Location: '.$selfUrl); exit; }

        if ($action==='save_settings') {
            $input = trim((string)($_POST['scan_path'] ?? ''));
            $wantAuto = !empty($_POST['auto_quarantine']);
            $ok = true;
            if ($input === '') {
                unset($config['scan_path']);
                $configuredScanPath=''; $scanRoot=$root; $paths['root']=$scanRoot; $scanPathWarning='';
            } else {
                $error = null;
                $resolved = resolveScanPath($input, $allowedBases, $error);
                if ($resolved === null) { $message=(string)($error ?: 'Invalid scan path.'); $messageClass='error'; $ok=false; }
                else { $config['scan_path']=$resolved; $configuredScanPath=$resolved; $scanRoot=$resolved; $paths['root']=$scanRoot; $scanPathWarning=''; }
            }
            if ($ok) {
                $config['auto_quarantine'] = $wantAuto;
                $autoQuarantine = $wantAuto; $paths['auto_quarantine'] = $wantAuto;
                $wantBackground = !empty($_POST['background_scan']);
                $config['background_scan'] = $wantBackground; $backgroundScan = $wantBackground;
                try {
                    writeJson($configFile, $config);
                    $message='Settings saved. Scanning '.$scanRoot.'. Auto-quarantine '.($wantAuto?'ON':'OFF').', background scans '.($wantBackground?'ON':'OFF').'.';
                    $messageClass='success';
                } catch (Throwable $error) { $message='Unable to save configuration: '.$error->getMessage(); $messageClass='error'; }
            }
        }

        if ($action==='capture_baseline') {
            try {
                $wpRootB = findWpRoot($scanRoot) ?? $scanRoot;
                if (!is_dir($wpRootB)) {
                    $message = 'The scan path is not a readable directory, so there is nothing to baseline.';
                    $messageClass = 'error';
                } else {
                    $map = captureBaseline($wpRootB, [$dataDir, $self, $scanner]);
                    writeJson($dataDir . DIRECTORY_SEPARATOR . 'baseline.json', $map);
                    $message = 'Baseline captured: ' . number_format(count($map)) . ' files recorded from '
                        . $wpRootB . '. Future scans report anything that has since changed. '
                        . 'Only capture a baseline on an install you believe is clean.';
                    $messageClass = 'success';
                }
            } catch (Throwable $error) {
                $message = 'Could not capture the baseline: ' . $error->getMessage();
                $messageClass = 'error';
            }
        }

        if ($action==='cancel_scan') {
            requestCancel($dataDir);
            // A background scan runs in its own process: ask it to stop, and if
            // it ignores the flag while stuck inside AMWScan, end the process.
            $st = readJson($statusFile);
            $pid = (int)($st['pid'] ?? 0);
            if ($pid > 0 && $backgroundScan && $pid !== getmypid()) {
                if (function_exists('posix_kill')) { @posix_kill($pid, 15); }
                elseif (execAllowed()) {
                    $out = []; $rc = 0;
                    if (DIRECTORY_SEPARATOR === '\\') @exec('taskkill /PID ' . (int)$pid . ' /T /F 2>NUL', $out, $rc);
                    else @exec('kill -TERM ' . (int)$pid . ' 2>/dev/null', $out, $rc);
                }
            }
            if (!empty($_POST['ajax'])) {
                header('Content-Type: application/json; charset=UTF-8');
                header('Cache-Control: no-store');
                echo json_encode(['ok'=>true,'message'=>'Stopping the scan...']);
                exit;
            }
            $message = 'Stop requested. The scan will halt shortly and keep whatever it already found.';
            $messageClass = 'warning';
        }

        if ($action==='scan') {
            if ($backgroundScan) {
                try {
                    $phpCli = detectCliPhp($config, $configFile); $paths['php_cli'] = $phpCli;
                    startBackgroundScan($paths, $dataDir, $phpCli); header('Location: '.$selfUrl.'?started=1'); exit; }
                catch(Throwable $error) {$message=$error->getMessage();$messageClass='error';}
            } else {
                $ajax = !empty($_POST['ajax']);
                // Release the session lock FIRST. PHP serialises requests that
                // share a session, so without this the progress polling would
                // sit in a queue behind the scan and the bar would never move.
                session_write_close();
                try {
                    $report = runScan($paths);
                    $flash = ['message'=>'Scan completed for '.$report['scan_path'].'. '.(int)$report['findings_count'].' active finding(s), '.(int)$report['excluded_count'].' excluded, '.(int)$report['quarantined_count'].' in quarantine.', 'class'=>((int)$report['findings_count']>0?'warning':'success')];
                } catch (Throwable $error) {
                    $flash = ['message'=>$error->getMessage(), 'class'=>'error'];
                }
                @session_start();
                $_SESSION['flash'] = $flash;
                session_write_close();
                if ($ajax) {
                    header('Content-Type: application/json; charset=UTF-8');
                    header('Cache-Control: no-store');
                    echo json_encode(['ok'=>$flash['class']!=='error','message'=>$flash['message'],'class'=>$flash['class']]);
                    exit;
                }
                $message = $flash['message']; $messageClass = $flash['class'];
            }
        }

        if ($action==='quarantine_selected' || $action==='exclude_selected') {
            $selected = array_map('strval', (array)($_POST['sel'] ?? []));
            $statusNow = readJson($statusFile);
            $current = is_array($statusNow['findings'] ?? null) ? $statusNow['findings'] : [];
            $byId = [];
            foreach ($current as $finding) {
                $file = findingPath(is_array($finding) ? $finding : []);
                if ($file !== '' && $file !== 'Path not parsed') $byId[findingId($file)] = $file;
            }
            $targets = [];
            foreach ($selected as $id) if (isset($byId[$id])) $targets[] = $byId[$id];
            $targets = array_values(array_unique($targets));

            if (!$targets) { $message='Nothing selected.'; $messageClass='error'; }
            elseif ($action==='exclude_selected') {
                if (saveExclusions($exclusionsFile, array_merge(readExclusions($exclusionsFile), $targets))) {
                    $message=count($targets).' path(s) added to exclusions.'; $messageClass='success';
                } else { $message='Unable to save exclusions. Check private-folder permissions.'; $messageClass='error'; }
            } else {
                $done=0; $errors=[];
                foreach ($targets as $file) {
                    try { quarantineFile($file, $scanRoot, $quarantineDir, $manifestFile); $done++; }
                    catch (Throwable $error) { $errors[] = $error->getMessage(); }
                }
                $message = $done.' file(s) moved to quarantine.'.($errors ? ' Problems: '.implode(' | ', array_slice($errors,0,4)) : '');
                $messageClass = $errors ? ($done ? 'warning' : 'error') : 'success';
            }
        }

        if ($action==='restore_selected' || $action==='delete_selected') {
            $manifest = syncQuarantine($quarantineDir, $manifestFile, $scanRoot);
            $selected = array_map('strval', (array)($_POST['qsel'] ?? []));
            $done=0; $errors=[];
            foreach ($selected as $id) {
                if (!isset($manifest[$id])) continue;
                try {
                    if ($action==='restore_selected') restoreQuarantined($manifest[$id], $quarantineDir, $allowedBases);
                    else deleteQuarantined($manifest[$id], $quarantineDir);
                    unset($manifest[$id]); $done++;
                } catch (Throwable $error) { $errors[] = $error->getMessage(); }
            }
            try { saveManifest($manifestFile, $manifest); } catch (Throwable) {}
            pruneEmptyDirs($quarantineDir);
            if (!$done && !$errors) { $message='Nothing selected.'; $messageClass='error'; }
            else {
                $verb = $action==='restore_selected' ? 'restored' : 'permanently deleted';
                $message = $done.' file(s) '.$verb.'.'.($errors ? ' Problems: '.implode(' | ', array_slice($errors,0,4)) : '');
                $messageClass = $errors ? ($done ? 'warning' : 'error') : 'success';
            }
        }

        if ($action==='save_exclusions') {
            $lines=preg_split('/\R/',(string)($_POST['exclusions']??''))?:[];
            if (saveExclusions($exclusionsFile,$lines)) {$message='Exclusions saved successfully.';$messageClass='success';}
            else {$message='Unable to save exclusions. Check private-folder permissions.';$messageClass='error';}
        }
    }
}

if (!$configured || !$authenticated) {
    $title=$configured?'Sign In':'First-Time Setup';
    ?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?=h(SHORT_NAME)?></title>
<script>try{var t=localStorage.getItem('gts_theme');if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}</script>
<style>
:root{--bg:#e9eef5;--surface:#fff;--border:#dde5ee;--text:#0f172a;--muted:#5b6b80;--brand:#0b5f8a;--bad-bg:#fee2e2;--bad-fg:#8a1c1c;--head:#0d1a2b;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#070d16;--surface:#101c2c;--border:#22344f;--text:#e7eef8;--muted:#94a6c0;--brand:#1c85c4;--bad-bg:#4a1414;--bad-fg:#ffb3b3;--head:#0a1523}}
:root[data-theme="dark"]{--bg:#070d16;--surface:#101c2c;--border:#22344f;--text:#e7eef8;--muted:#94a6c0;--brand:#1c85c4;--bad-bg:#4a1414;--bad-fg:#ffb3b3;--head:#0a1523}
*{box-sizing:border-box}html{color-scheme:light dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:var(--bg);color:var(--text);font:14px/1.5 var(--sans)}
.card{width:min(420px,100%);background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:30px;box-shadow:0 20px 50px rgba(8,15,30,.18)}
.brand{display:flex;align-items:center;gap:11px;margin-bottom:22px}
.brand strong{display:block;font-size:16px}.brand span{display:block;font-size:11.5px;color:var(--muted)}
h2{margin:0 0 4px;font-size:19px}
.sub{color:var(--muted);margin:0 0 18px;font-size:13px}
label{display:block;font-weight:700;margin:14px 0 6px;font-size:13px}
input{width:100%;padding:12px;font:15px var(--sans);color:var(--text);background:var(--surface);border:1px solid var(--border);border-radius:9px}
input:focus{outline:2px solid var(--brand);outline-offset:1px}
button{width:100%;margin-top:20px;padding:13px;background:var(--brand);color:#fff;border:0;border-radius:9px;font-weight:700;font-size:15px;cursor:pointer;font-family:inherit}
button:hover{filter:brightness(1.08)}
.err{background:var(--bad-bg);color:var(--bad-fg);padding:11px 13px;border-radius:9px;font-weight:600;font-size:13px}
.foot{margin-top:18px;text-align:center;color:var(--muted);font-size:11.5px}

<?= footerCss() ?>
</style></head><body><main class="card">
<div class="brand"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="1.8" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4" stroke-linecap="round"/></svg><span><strong><?=h(SHORT_NAME)?></strong><span>Powered by AMWScan</span></span></div>
<h2><?=h($title)?></h2><p class="sub"><?=$configured?'Enter your password to open the security dashboard.':'Choose a password to protect this dashboard.'?></p>
<?php if($message):?><p class="err"><?=h($message)?></p><?php endif;?>
<form method="post"><input type="hidden" name="action" value="<?=$configured?'login':'setup'?>">
<label for="pw">Password</label><input id="pw" type="password" name="password" minlength="<?=$configured?1:12?>" required autofocus autocomplete="<?=$configured?'current-password':'new-password'?>">
<?php if(!$configured):?><label for="pw2">Confirm password</label><input id="pw2" type="password" name="confirm" minlength="12" required autocomplete="new-password"><?php endif;?>
<button><?=$configured?'Sign In':'Create Password'?></button></form>
<?php renderFooter($installationId, true); ?>
</main></body></html><?php exit;
}

// Live progress endpoint polled by the dashboard while a scan runs.
if (isset($_GET['status'])) {
    session_write_close();
    $st = readJson($statusFile, ['completion_status'=>'not_run']);
    $running = scanIsRunning($lockFile);
    $percent = 0; $total = 0;
    if ($running && !empty($st['raw_log'])) {
        [$percent, $total] = tailProgress($reportsDir . '/' . basename((string)$st['raw_log']));
    }
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');
    echo json_encode([
        'running'=>$running,'percent'=>$percent,'files'=>$total,
        'completion'=>(string)($st['completion_status']??'not_run'),
        'result'=>(string)($st['security_result']??'unavailable'),
        'findings'=>(int)($st['findings_count']??0),
        'started_at'=>(string)($st['started_at']??''),
    ]);
    exit;
}

if (isset($_GET['report'])) {
    $name=basename((string)$_GET['report']);
    if (preg_match('/^scan_[0-9_-]+\.txt$/',$name)!==1) { http_response_code(400); exit('Invalid report.'); }
    $file=$reportsDir.'/'.$name;
    if (!is_file($file)) { http_response_code(404); exit('Report not found.'); }
    header('Content-Type:text/plain;charset=UTF-8'); readfile($file); exit;
}

if ($message === '' && !empty($_SESSION['flash']['message'])) {
    $message = (string)$_SESSION['flash']['message'];
    $messageClass = (string)($_SESSION['flash']['class'] ?? '');
    unset($_SESSION['flash']);
}
$status=readJson($statusFile,['completion_status'=>'not_run','security_result'=>'unavailable']);
$history=[]; foreach(array_slice(reportFiles($reportsDir),0,20) as $file){$row=readJson($file);if($row)$history[]=$row;}
$findings=is_array($status['findings']??null)?$status['findings']:[];
$rules=readExclusions($exclusionsFile);
$quarantine=syncQuarantine($quarantineDir,$manifestFile,$scanRoot);
uasort($quarantine, static fn(array $a, array $b): int => strcmp((string)($b['quarantined_at']??''), (string)($a['quarantined_at']??'')));
$completionLabels=['completed'=>'Completed','failed'=>'Failed','running'=>'Running','not_run'=>'Not Run','cancelled'=>'Stopped','partial'=>'Partial'];
$resultLabels=['clean'=>'Clean','findings'=>'Findings Detected','pending'=>'Pending','unavailable'=>'Unavailable'];
$completion=(string)($status['completion_status']??'not_run');
$result=(string)($status['security_result']??'unavailable');
$running=scanIsRunning($lockFile);
$justStarted=isset($_GET['started']);
if ($running) { $completion='running'; $result='pending'; }
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?=h(SHORT_NAME)?></title>
<script>try{var t=localStorage.getItem('gts_theme');if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}</script>
<style>
:root{
--bg:#eaeff5;--surface:#fff;--surface2:#f6f9fc;--border:#dde5ee;--line:#eef2f7;
--text:#0f172a;--muted:#5b6b80;--head:#0d1a2b;--head-text:#e8eef7;--head-muted:#8fa3bd;
--brand:#0b5f8a;--brand-ink:#fff;--brand-soft:#e6f1f8;
--ok-bg:#dcfce7;--ok-fg:#14532d;--warn-bg:#fef1c7;--warn-fg:#7c4a03;
--bad-bg:#fee2e2;--bad-fg:#8a1c1c;--info-bg:#dbeafe;--info-fg:#1d3f8f;--idle-bg:#e3e8ef;--idle-fg:#475569;
--shadow:0 1px 2px rgba(15,23,42,.05),0 6px 18px rgba(15,23,42,.06);
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
--bg:#080e18;--surface:#101c2c;--surface2:#16243a;--border:#22344f;--line:#1a2839;
--text:#e7eef8;--muted:#94a6c0;--head:#0a1523;--head-text:#e7eef8;--head-muted:#8ba0bd;
--brand:#1c85c4;--brand-ink:#fff;--brand-soft:#12293c;
--ok-bg:#0f3d24;--ok-fg:#8ef0b6;--warn-bg:#43300a;--warn-fg:#ffd88a;
--bad-bg:#4a1414;--bad-fg:#ffb3b3;--info-bg:#122c52;--info-fg:#a9c9ff;--idle-bg:#1c2a3d;--idle-fg:#a4b5cc;
--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35);
}}
:root[data-theme="dark"]{
--bg:#080e18;--surface:#101c2c;--surface2:#16243a;--border:#22344f;--line:#1a2839;
--text:#e7eef8;--muted:#94a6c0;--head:#0a1523;--head-text:#e7eef8;--head-muted:#8ba0bd;
--brand:#1c85c4;--brand-ink:#fff;--brand-soft:#12293c;
--ok-bg:#0f3d24;--ok-fg:#8ef0b6;--warn-bg:#43300a;--warn-fg:#ffd88a;
--bad-bg:#4a1414;--bad-fg:#ffb3b3;--info-bg:#122c52;--info-fg:#a9c9ff;--idle-bg:#1c2a3d;--idle-fg:#a4b5cc;
--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35);
}
*{box-sizing:border-box}
html{color-scheme:light dark}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 var(--sans);-webkit-text-size-adjust:100%}
.wrap{width:min(1160px,100% - 32px);margin-inline:auto}
h1,h2,h3{margin:0;line-height:1.25}
code,.mono{font-family:var(--mono);font-size:.92em;overflow-wrap:anywhere}
a{color:var(--brand)}

/* header */
.topbar{background:var(--head);color:var(--head-text);border-bottom:1px solid rgba(255,255,255,.07)}
.topbar .wrap{display:flex;align-items:center;gap:14px;min-height:62px;padding:10px 0}
.logo{display:flex;align-items:center;gap:11px;min-width:0}
.logo svg{flex:0 0 auto}
.logo-txt{min-width:0}
.logo-txt strong{display:block;font-size:15px;letter-spacing:.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.logo-txt span{display:block;font-size:11px;color:var(--head-muted);letter-spacing:.3px}
.topbar-actions{margin-left:auto;display:flex;align-items:center;gap:8px}
.iconbtn{background:rgba(255,255,255,.09);color:var(--head-text);border:1px solid rgba(255,255,255,.14);border-radius:8px;width:38px;height:38px;display:grid;place-items:center;cursor:pointer;padding:0}
.iconbtn:hover{background:rgba(255,255,255,.16)}
.topbar form{margin:0}
.linkbtn{background:transparent;color:var(--head-muted);border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:9px 13px;font-weight:600;cursor:pointer;font-size:13px}
.linkbtn:hover{color:var(--head-text)}

main{padding:20px 0 56px}

/* hero */
.hero{background:var(--surface);border:1px solid var(--border);border-radius:14px;box-shadow:var(--shadow);padding:18px;margin-bottom:14px;display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center}
.verdict{display:flex;align-items:center;gap:14px;min-width:0}
.vdot{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;flex:0 0 auto}
.vdot svg{width:24px;height:24px}
.v-clean .vdot{background:var(--ok-bg);color:var(--ok-fg)}
.v-findings .vdot{background:var(--warn-bg);color:var(--warn-fg)}
.v-unavailable .vdot,.v-pending .vdot{background:var(--idle-bg);color:var(--idle-fg)}
.v-failed .vdot{background:var(--bad-bg);color:var(--bad-fg)}
.vtext{min-width:0}
.vtext h1{font-size:21px}
.vtext p{margin:3px 0 0;color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.btn{background:var(--brand);color:var(--brand-ink);border:0;border-radius:9px;padding:12px 20px;font-weight:700;font-size:14px;cursor:pointer;min-height:44px;font-family:inherit}
.btn:hover{filter:brightness(1.08)}
.btn[disabled]{opacity:.55;cursor:default;filter:none}
.btn-ghost{background:transparent;color:var(--brand);border:1px solid var(--border)}
.btn-danger{background:#b42318;color:#fff}
.btn-sm{padding:9px 14px;min-height:38px;font-size:13px}

/* stats */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:12px;margin-bottom:14px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 15px;box-shadow:var(--shadow)}
.stat .k{font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:var(--muted);font-weight:700}
.stat .v{font-size:22px;font-weight:800;margin-top:6px;letter-spacing:-.3px}
.stat .v.small{font-size:14px;font-weight:700;word-break:break-word}

/* badges */
.badge{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.b-completed,.b-clean,.b-success{background:var(--ok-bg);color:var(--ok-fg)}
.b-findings,.b-warning{background:var(--warn-bg);color:var(--warn-fg)}
.b-failed,.b-error{background:var(--bad-bg);color:var(--bad-fg)}
.b-running,.b-pending{background:var(--info-bg);color:var(--info-fg)}
.b-not_run,.b-unavailable{background:var(--idle-bg);color:var(--idle-fg)}
.b-cancelled,.b-partial{background:var(--warn-bg);color:var(--warn-fg)}
.chip{background:var(--brand-soft);color:var(--brand);border-radius:999px;padding:2px 9px;font-size:12px;font-weight:800}
.chip.alert{background:var(--warn-bg);color:var(--warn-fg)}

/* messages */
.msg{padding:12px 14px;border-radius:10px;margin-bottom:14px;font-weight:600;border:1px solid transparent}
.m-success{background:var(--ok-bg);color:var(--ok-fg)}
.m-warning{background:var(--warn-bg);color:var(--warn-fg)}
.m-error{background:var(--bad-bg);color:var(--bad-fg)}
.m-running{background:var(--info-bg);color:var(--info-fg)}

/* collapsible panels */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:13px;box-shadow:var(--shadow);margin-bottom:13px;overflow:hidden}
.panel>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:11px;padding:14px 16px;font-weight:700;font-size:14px;user-select:none}
.panel>summary::-webkit-details-marker{display:none}
.panel>summary:hover{background:var(--surface2)}
.panel>summary .sub{color:var(--muted);font-weight:500;font-size:12px}
.panel>summary .chev{margin-left:auto;flex:0 0 auto;width:8px;height:8px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(45deg);transition:transform .18s;margin-right:4px}
.panel[open]>summary .chev{transform:rotate(225deg)}
.panel[open]>summary{border-bottom:1px solid var(--line)}
.pbody{padding:16px}
.pico{width:18px;height:18px;flex:0 0 auto;color:var(--muted)}

/* tables */
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--surface2);font-size:11px;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);white-space:nowrap;font-weight:800}
tbody tr:last-child td{border-bottom:0}
td.num,td.when{white-space:nowrap;font-variant-numeric:tabular-nums}
td.pathcell{max-width:320px}
td.pathcell .mono{display:block;overflow-wrap:anywhere}
.check{width:18px;height:18px;flex:0 0 auto;accent-color:var(--brand)}

/* findings */
.selbar{display:flex;align-items:center;gap:10px;padding:11px 13px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;margin-bottom:12px;font-weight:700;font-size:13px}
.finding{border:1px solid var(--border);border-radius:11px;margin-bottom:10px;overflow:hidden;background:var(--surface)}
.finding-top{display:flex;gap:11px;padding:13px;align-items:flex-start}
.finding-main{min-width:0;flex:1}
.finding-file{font-family:var(--mono);font-size:13px;font-weight:600;overflow-wrap:anywhere}
.meta{display:flex;flex-wrap:wrap;gap:7px;margin-top:8px}
.tag{background:var(--surface2);border:1px solid var(--border);color:var(--muted);border-radius:6px;padding:3px 8px;font-size:11.5px;font-weight:700}
.tag b{color:var(--text);font-weight:700}
details.tech{border-top:1px solid var(--line)}
details.tech>summary{cursor:pointer;padding:9px 13px;font-size:12px;color:var(--muted);font-weight:700;list-style:none}
details.tech>summary::-webkit-details-marker{display:none}
pre{margin:0;padding:13px;background:var(--surface2);border-top:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--mono);font-size:12px;max-height:340px;overflow:auto}
.actions{display:flex;flex-wrap:wrap;gap:9px;margin-top:13px}

/* forms */
label.fld{display:block;font-weight:700;margin-bottom:6px;font-size:13px}
input[type=text],input[type=password],textarea{width:100%;padding:11px 12px;font:14px/1.4 var(--sans);color:var(--text);background:var(--surface);border:1px solid var(--border);border-radius:9px}
textarea{min-height:140px;font-family:var(--mono);font-size:13px;resize:vertical}
input:focus,textarea:focus{outline:2px solid var(--brand);outline-offset:1px}
.hint{color:var(--muted);font-size:12.5px;margin:7px 0 0}
.toggle{display:flex;gap:11px;align-items:flex-start;margin:15px 0;padding:12px;border:1px solid var(--border);border-radius:10px;background:var(--surface2)}
.toggle b{display:block;font-size:13px}
.toggle .hint{margin-top:4px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:13px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:7px 16px;font-size:13px}
.kv dt{color:var(--muted);font-weight:700;white-space:nowrap}
.kv dd{margin:0;overflow-wrap:anywhere}
.kv.diag{gap:10px 16px;align-items:center}
.kv.diag dt{color:var(--text)}
hr{border:0;border-top:1px solid var(--line);margin:16px 0}

/* severity mix - one proportional bar plus a legend, sized to its container */
.sevwrap{border:1px solid var(--border);background:var(--surface2);border-radius:10px;padding:13px;margin-bottom:13px}
.sevhead{display:flex;align-items:baseline;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:9px}
.sevhead b{font-size:11px;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}
.sevhead span{font-size:12px;color:var(--muted)}
.sevtrack{display:flex;height:10px;border-radius:999px;overflow:hidden;background:var(--line)}
.sevtrack i{display:block;height:100%}
.sevlegend{display:flex;flex-wrap:wrap;gap:7px;margin-top:10px}
.sevkey{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);background:var(--surface);border-radius:7px;padding:4px 9px;font-size:12px;font-weight:700}
.sevkey em{width:9px;height:9px;border-radius:3px;flex:0 0 auto}
.sevkey s{text-decoration:none;color:var(--muted);font-weight:600}
.sv-crit{background:#c2410c}.sv-high{background:#d97706}.sv-med{background:#2563eb}.sv-low{background:#64748b}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .sv-crit{background:#fb923c}:root:not([data-theme="light"]) .sv-high{background:#fbbf24}:root:not([data-theme="light"]) .sv-med{background:#60a5fa}:root:not([data-theme="light"]) .sv-low{background:#94a3b8}}
:root[data-theme="dark"] .sv-crit{background:#fb923c}
:root[data-theme="dark"] .sv-high{background:#fbbf24}
:root[data-theme="dark"] .sv-med{background:#60a5fa}
:root[data-theme="dark"] .sv-low{background:#94a3b8}

/* progress overlay */
.overlay{display:none;position:fixed;inset:0;background:rgba(6,12,22,.78);backdrop-filter:blur(3px);z-index:999;place-items:center;padding:18px}
.overlay.on{display:grid}
.obox{width:min(480px,100%);background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;box-shadow:0 30px 70px rgba(0,0,0,.4);text-align:center}
.obox .vdot{margin:0 auto 12px}
.obox h2{font-size:17px}
.obox p{color:var(--muted);margin:7px 0 0;font-size:13px}
.track{height:9px;background:var(--idle-bg);border-radius:999px;overflow:hidden;margin:17px 0 9px}
.bar{height:100%;width:3%;background:linear-gradient(90deg,var(--brand),#38bdf8);border-radius:999px;transition:width .6s ease}
.pct{font-variant-numeric:tabular-nums;font-weight:800;font-size:13px}

@media (max-width:820px){
  .wrap{width:calc(100% - 22px)}
  .hero{grid-template-columns:1fr}
  .hero form,.hero .btn{width:100%}
  .two{grid-template-columns:1fr}
}
@media (max-width:700px){
  table.stack thead{display:none}
  table.stack tbody tr{display:block;border:1px solid var(--border);border-radius:10px;margin-bottom:10px;padding:5px 3px;background:var(--surface)}
  table.stack tbody td{display:flex;gap:14px;justify-content:space-between;align-items:flex-start;border:0;padding:7px 11px;white-space:normal;max-width:none}
  table.stack tbody td::before{content:attr(data-label);color:var(--muted);font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.4px;flex:0 0 40%}
  table.stack tbody td.check-cell{justify-content:flex-start}
  table.stack tbody td.check-cell::before{content:"Select";flex:0 0 auto}
  .stats{grid-template-columns:1fr 1fr}
  .kv{grid-template-columns:1fr}
  .kv dd{margin-bottom:6px}
}
<?= footerCss() ?>
</style></head>
<body>
<div class="overlay" id="overlay"><div class="obox">
  <div class="vdot" style="background:var(--info-bg);color:var(--info-fg)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/></svg></div>
  <h2><?=h(SHORT_NAME)?></h2>
  <p id="ptext">Starting scan...</p>
  <div class="track"><div class="bar" id="bar"></div></div>
  <p class="pct" id="ppct">&nbsp;</p>
  <p><?=$backgroundScan?'The scan runs on the server. You can close this page.':'Keep this page open until the scan finishes.'?></p>
  <button class="btn btn-ghost btn-sm" type="button" id="stopBtn" style="margin-top:4px">Stop scan</button>
  <p class="pct" id="stopnote" style="margin-top:6px">&nbsp;</p>
</div></div>

<header class="topbar"><div class="wrap">
  <div class="logo">
    <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="1.8" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4" stroke-linecap="round"/></svg>
    <span class="logo-txt"><strong><?=h(SHORT_NAME)?></strong><span>Powered by AMWScan &middot; v<?=h(APP_VERSION)?></span></span>
  </div>
  <div class="topbar-actions">
    <button class="iconbtn" id="themeBtn" type="button" title="Switch light / dark" aria-label="Switch light or dark theme"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/></svg></button>
    <form method="post"><input type="hidden" name="action" value="logout"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><button class="linkbtn">Sign Out</button></form>
  </div>
</div></header>

<main class="wrap">
<?php
$verdictClass = $running ? 'pending' : ($completion==='failed' ? 'failed' : (($completion==='cancelled'||$completion==='partial') ? 'findings' : $result));
$verdictTitle = $running ? 'Scan in progress' : ($completion==='not_run' ? 'No scan yet' : ($completion==='cancelled' ? 'Scan stopped - partial results' : ($completion==='partial' ? 'Partial scan - see what did not run' : ($completion==='failed' ? 'Last scan failed' :($result==='clean' ? 'No malware detected' : ($result==='findings' ? (int)($status['findings_count']??0).' finding'.(((int)($status['findings_count']??0))===1?'':'s').' need review' : 'Status unavailable'))))));
$lastRun = (string)($status['finished_at'] ?? '');
?>
<section class="hero v-<?=h($verdictClass)?>">
  <div class="verdict">
    <span class="vdot"><?php if($verdictClass==='clean'):?><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg><?php elseif($verdictClass==='findings'):?><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 9v5M12 17.5v.5"/><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0Z" stroke-linejoin="round"/></svg><?php else:?><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16v.5"/></svg><?php endif;?></span>
    <div class="vtext">
      <h1><?=h($verdictTitle)?></h1>
      <p>Scanning <code><?=h($scanRoot)?></code><?php if($lastRun!==''):?> &middot; last scan <?=h(str_replace('T',' ',substr($lastRun,0,19)))?><?php endif;?></p>
      <div style="display:flex;gap:12px;margin-top:12px;flex-wrap:wrap;"><span class="badge b-<?=h($completion)?>" title="Scan completion status"><strong>Status:</strong> <?=h($completionLabels[$completion]??'Unknown')?></span><span class="badge b-<?=h($result)?>" title="Security result"><strong>Result:</strong> <?=h($resultLabels[$result]??'Unknown')?></span></div>
    </div>
  </div>
  <form method="post" id="scanForm"><input type="hidden" name="action" value="scan"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><button class="btn" type="submit" <?=$running?'disabled':''?>><?=$running?'Scan running...':'Run Scan Now'?></button></form>
</section>

<?php if($scanPathWarning):?><div class="msg m-error"><?=h($scanPathWarning)?></div><?php endif;?>
<?php if($completion==='cancelled'):?>
  <div class="msg m-warning">
    <strong>Scan stopped before it finished.</strong>
    Everything found up to that point is listed below - treat it as a partial picture, not a clean bill of health.
    <?php if(!empty($status['files_scanned'])):?> Checked <?=number_format((int)$status['files_scanned'])?> file(s) before stopping.<?php endif;?>
  </div>
<?php endif;?>
<?php if(!empty($status['not_run'])):?>
  <div class="msg m-warning">
    <strong>Not everything ran.</strong> This scan did not include:
    <?=h(implode('; ', (array)$status['not_run']))?>.
    Treat the result as covering only what is listed under Integrity below.
    <?php if(!empty($status['cli_error'])):?><br><small><?=h((string)$status['cli_error'])?></small><?php endif;?>
  </div>
<?php endif;?>
<?php if($completion==='failed'):?>
  <div class="msg m-error">
    <strong>Last scan failed &mdash; nothing about this site was checked.</strong>
    <?php if(!empty($status['error_message'])):?><br><?=h((string)$status['error_message'])?><?php endif;?>
    <?php if(!empty($status['exit_code'])):?><br>Exit code: <code><?=h((string)($status['exit_code']))?></code><?php endif;?>
    <details style="margin-top:8px;cursor:pointer;"><summary style="cursor:pointer;color:inherit;"><small>View diagnostics</small></summary><pre style="font-size:0.8em;margin-top:8px;overflow-x:auto;"><?php
    $diagCandidates = phpCandidates();
    $diagWorking = (string)($status['php_binary'] ?? '');
    $diagnostics = [
      'PHP CLI'      => $diagWorking !== '' ? '✓ ' . $diagWorking : '✗ No working binary found',
      'Paths tried'  => $diagCandidates ? $diagCandidates : ['none matched on this server'],
      'Platform'     => PHP_OS_FAMILY . ' / ' . PHP_SAPI,
      'exec()'       => execAllowed() ? '✓ Available' : '✗ Disabled',
      'Memory'       => (string)ini_get('memory_limit'),
    ];
    echo h(json_encode($diagnostics,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
    ?></pre></details>
  </div>
<?php endif;?>
<?php if($justStarted&&!$message):?><div class="msg m-running">Scan started in the background. This page updates on its own.</div><?php endif;?>
<?php if($message):?><div class="msg m-<?=h($messageClass?:'running')?>"><?=h($message)?></div><?php endif;?>

<section class="stats">
  <div class="stat"><div class="k">Status</div><div class="v"><span class="badge b-<?=h($completion)?>"><?=h($completionLabels[$completion]??'Unknown')?></span></div></div>
  <div class="stat"><div class="k">Result</div><div class="v"><span class="badge b-<?=h($result)?>"><?=h($resultLabels[$result]??'Unknown')?></span></div></div>
  <div class="stat"><div class="k">Total findings</div><div class="v"><?=number_format((int)($status['findings_count']??0))?></div></div>
  <div class="stat"><div class="k">Quarantined</div><div class="v"><?=number_format(count($quarantine))?></div></div>
  <div class="stat"><div class="k">Files scanned</div><div class="v"><?=number_format((int)($status['files_scanned']??0))?></div></div>
  <div class="stat"><div class="k">Duration</div><div class="v small"><?=number_format((int)($status['duration_seconds']??0))?> sec</div></div>
</section>

<details class="panel" id="p-findings" <?=$findings?'open':''?>><summary>
  <svg class="pico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v5M12 17.5v.5"/><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0Z" stroke-linejoin="round"/></svg>
  Findings <?php if($findings):?><span class="chip alert"><?=count($findings)?></span><?php else:?><span class="chip"><?=0?></span><?php endif;?>
  <span class="sub"><?=h($lastRun!==''?'from '.str_replace('T',' ',substr($lastRun,0,19)):'no completed scan yet')?></span><span class="chev"></span></summary>
  <div class="pbody">
  <?php if(!$findings):?><p class="hint">Nothing flagged in the latest scan.</p><?php else:$shown=array_slice($findings,0,MAX_FINDINGS_RENDERED);
    $sev=['critical'=>0,'high'=>0,'medium'=>0,'low'=>0];
    foreach($findings as $f){$sev[findingSeverity($f)]++;}
    $sevTotal=max(1,array_sum($sev));
    $sevMeta=['critical'=>['Critical','sv-crit','runs attacker code now'],'high'=>['High','sv-high','malicious, needs a trigger'],'medium'=>['Medium','sv-med','review by hand'],'low'=>['Low','sv-low','weak signal']];
  ?>
    <div class="sevwrap">
      <div class="sevhead"><b>Severity mix</b><span><?=number_format(count($findings))?> finding<?=count($findings)===1?'':'s'?> ranked by how directly each one gives an attacker control</span></div>
      <div class="sevtrack">
        <?php foreach($sevMeta as $key=>$meta): if($sev[$key]<=0) continue; ?>
          <i class="<?=h($meta[1])?>" style="width:<?=round($sev[$key]*100/$sevTotal,2)?>%" title="<?=h($meta[0].': '.$sev[$key])?>"></i>
        <?php endforeach;?>
      </div>
      <div class="sevlegend">
        <?php foreach($sevMeta as $key=>$meta):?>
          <span class="sevkey" title="<?=h($meta[2])?>"><em class="<?=h($meta[1])?>"></em><?=h($meta[0])?> <?=number_format($sev[$key])?> <s><?=round($sev[$key]*100/$sevTotal)?>%</s></span>
        <?php endforeach;?>
      </div>
    </div>
    <?php if(count($findings)>count($shown)):?><div class="msg m-warning">Showing the first <?=count($shown)?> of <?=count($findings)?>. The full list is in the raw report.</div><?php endif;?>
    <?php if(!empty($status['findings_truncated'])):?><div class="msg m-warning">This scan produced more findings than the dashboard stores. See the raw report for everything.</div><?php endif;?>
    <form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>">
    <label class="selbar"><input type="checkbox" class="check" id="allFindings"> Select all <?=count($shown)?> findings</label>
    <div style="max-height:600px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;padding:8px;">
    <?php foreach($shown as $i=>$finding):
      $shownPath=(string)($finding['file']??'');
      $realPath=findingPath($finding);
      $known=$shownPath!==''&&$shownPath!=='Path not parsed';
      $gone=$known&&$realPath!==''&&!is_file($realPath);
      $sevKey=findingSeverity($finding);
      $sevInfo=$sevMeta[$sevKey]??['Low','sv-low',''];
      // The signature engine names the exact pattern in 'threat'; AMWScan uses
      // 'classification'. Showing only the latter reduced every signature hit
      // to a meaningless "Finding / Pattern match" pair.
      $label=trim((string)($finding['threat']??''))?:trim((string)($finding['classification']??''))?:'Finding';
      $detail=trim((string)($finding['details']??''));
      if($detail===''&&!empty($finding['threat'])) $detail='Matched signature: '.(string)$finding['threat']."\nFile: ".$realPath;
    ?>
      <article class="finding">
        <div class="finding-top">
          <?php if($known):?><input type="checkbox" class="check fchk" name="sel[]" value="<?=h(findingId($realPath))?>" aria-label="Select finding <?=($i+1)?>"><?php endif;?>
          <div class="finding-main">
            <div class="finding-file"><?=h($shownPath!==''?$shownPath:'Path could not be parsed')?></div>
            <div class="meta">
              <span class="sevkey" title="<?=h($sevInfo[2])?>"><em class="<?=h($sevInfo[1])?>"></em><?=h($sevInfo[0])?></span>
              <span class="tag"><?=h($label)?></span>
              <?php if(!empty($finding['trigger'])):?><span class="tag">Trigger: <b><?=h((string)$finding['trigger'])?></b></span><?php endif;?>
              <?php if(!empty($finding['sources'])):?><span class="tag"><?=h(implode(' + ', (array)$finding['sources']))?></span><?php endif;?>
              <?php if($gone):?><span class="badge b-completed">No longer on disk</span><?php else:?><span class="badge b-findings">Review required</span><?php endif;?>
            </div>
          </div>
        </div>
        <?php if($detail!==''):?><details class="tech"><summary>Technical details</summary><pre><?=h($detail)?></pre></details><?php endif;?>
      </article>
    <?php endforeach;?>
    </div>
    <div class="actions"><button class="btn btn-sm" name="action" value="quarantine_selected">Quarantine Selected</button><button class="btn btn-sm btn-ghost" name="action" value="exclude_selected">Mark Selected As False Positive</button></div>
    </form>
  <?php endif;?>
  </div>
</details>

<?php
$L = is_array($status['layers'] ?? null) ? $status['layers'] : [];
// Detect WordPress at render time, not from the last scan: capturing a
// baseline is the natural FIRST action, before any scan has ever run.
$uiWpRoot = findWpRoot($scanRoot);
$uiWpVer  = $uiWpRoot ? wpVersion($uiWpRoot) : null;
$uiVerifyRoot = $uiWpRoot ?? $scanRoot;
$uiBaseFile = $dataDir . DIRECTORY_SEPARATOR . 'baseline.json';
$uiHasBase  = is_file($uiBaseFile);
?>
<details class="panel" id="p-integrity" open><summary>
  <svg class="pico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>
  Integrity
  <span class="sub"><?=$uiWpVer ? 'WordPress '.h($uiWpVer) : 'generic PHP project'?></span>
  <span class="chev"></span></summary>
  <div class="pbody">
  <?php if(!is_dir($uiVerifyRoot)):?>
    <p class="hint">The scan path is not a readable directory, so integrity checking cannot run.</p>
  <?php else:?>
    <?php if($uiWpRoot === null):?>
      <p class="hint" style="margin-bottom:12px">No WordPress install here, so core checksum verification does not apply. Baseline drift and the structural rules still work - they are plain file inspection and apply to any PHP project.</p>
    <?php endif;?>
    <dl class="kv diag">
      <dt>Core checksums</dt><dd>
      <?php $c = $L['core'] ?? null; if(is_array($c) && isset($c['verified'])):?>
        <span class="badge b-<?=($c['modified']||$c['unknown'])?'findings':'clean'?>"><?=number_format((int)$c['verified'])?> files verified</span>
        <?php if($c['modified']):?> <span class="badge b-failed"><?=(int)$c['modified']?> modified</span><?php endif;?>
        <?php if($c['unknown']):?> <span class="badge b-failed"><?=(int)$c['unknown']?> unknown in core</span><?php endif;?>
        <?php if($c['missing']):?> <span class="badge b-findings"><?=(int)$c['missing']?> missing</span><?php endif;?>
        <br><small class="hint">source: <?=h((string)$c['source'])?></small>
      <?php elseif(is_array($c)):?>
        <span class="badge b-unavailable">unavailable</span> <small class="hint"><?=h((string)($c['error'] ?? ''))?></small>
      <?php elseif($uiWpRoot === null):?>
        <span class="badge b-unavailable">not applicable</span> <small class="hint">WordPress only - no authority publishes hashes for a generic PHP project.</small>
      <?php else:?><span class="badge b-unavailable">not run</span><?php endif;?>
      </dd>

      <dt>Baseline</dt><dd>
      <?php $b = $L['baseline'] ?? null; if(is_array($b)):?>
        <span class="badge b-<?=($b['added']||$b['modified']||$b['removed'])?'findings':'clean'?>"><?=number_format((int)$b['unchanged'])?> unchanged</span>
        <?php if($b['added']):?> <span class="badge b-findings"><?=(int)$b['added']?> new</span><?php endif;?>
        <?php if($b['modified']):?> <span class="badge b-failed"><?=(int)$b['modified']?> changed</span><?php endif;?>
        <?php if($b['removed']):?> <span class="badge b-unavailable"><?=(int)$b['removed']?> removed</span><?php endif;?>
        <br><small class="hint">captured <?=h(str_replace('T',' ',substr((string)$b['captured_at'],0,19)))?></small>
      <?php elseif($uiHasBase):?>
        <span class="badge b-clean">captured</span>
        <small class="hint">No scan has compared against it yet.</small>
      <?php else:?>
        <span class="badge b-unavailable">not captured</span>
        <small class="hint">Covers plugins and themes, which WordPress.org cannot verify.</small>
      <?php endif;?>
      </dd>
    </dl>
    <form method="post" style="margin-top:14px">
      <input type="hidden" name="action" value="capture_baseline">
      <input type="hidden" name="csrf" value="<?=h($csrf)?>">
      <button class="btn btn-sm btn-ghost" type="submit"><?=$uiHasBase?'Re-capture baseline':'Capture baseline'?></button>
      <span class="hint" style="margin-left:10px">Records a hash of every file. Only do this on an install you believe is clean.</span>
    </form>
  <?php endif;?>
  </div>
</details>

<details class="panel" id="p-quarantine" <?=$quarantine?'open':''?>><summary>
  <svg class="pico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="6" width="18" height="15" rx="2"/><path d="M3 10h18M8 6V3h8v3"/></svg>
  Quarantine <span class="chip"><?=count($quarantine)?></span><span class="sub">isolated files, restorable</span><span class="chev"></span></summary>
  <div class="pbody">
  <?php if(!$quarantine):?><p class="hint">Quarantine is empty.</p><?php else:?>
    <form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>">
    <label class="selbar"><input type="checkbox" class="check" id="allQuarantine"> Select all <?=count($quarantine)?> files</label>
    <div class="tablewrap"><table class="stack"><thead><tr><th></th><th>Original location</th><th>Moved</th><th>Size</th><th>By</th></tr></thead><tbody>
    <?php foreach($quarantine as $entry):?><tr>
      <td class="check-cell"><input type="checkbox" class="check qchk" name="qsel[]" value="<?=h((string)$entry['id'])?>" aria-label="Select file"></td>
      <td class="pathcell" data-label="Original location"><span class="mono"><?=h((string)($entry['original']??''))?></span></td>
      <td class="when" data-label="Moved"><?=h(str_replace('T',' ',substr((string)($entry['quarantined_at']??''),0,19)))?></td>
      <td class="num" data-label="Size"><?=h(humanSize((int)($entry['size']??0)))?></td>
      <td data-label="By"><span class="tag"><?=h((string)($entry['source']??'auto'))?></span></td>
    </tr><?php endforeach;?>
    </tbody></table></div>
    <div class="actions"><button class="btn btn-sm" name="action" value="restore_selected">Restore Selected</button><button class="btn btn-sm btn-danger" name="action" value="delete_selected" id="deleteBtn">Delete Permanently</button></div>
    <p class="hint">Restore puts each file back exactly where it came from. Deleting cannot be undone.</p>
    </form>
  <?php endif;?>
  </div>
</details>

<details class="panel" id="p-history"><summary>
  <svg class="pico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
  Scan History <span class="chip"><?=count($history)?></span><span class="sub">last <?=count($history)?> scans</span><span class="chev"></span></summary>
  <div class="pbody">
  <?php if(!$history):?><p class="hint">No scans recorded yet.</p><?php else:?>
    <div class="tablewrap"><table class="stack"><thead><tr><th>Finished</th><th>Result</th><th>Path</th><th>Files</th><th>Findings</th><th>Quar.</th><th>Time</th><th>Report</th></tr></thead><tbody>
    <?php foreach($history as $row):$c=(string)($row['completion_status']??'failed');$r=(string)($row['security_result']??'unavailable');$raw=basename((string)($row['raw_log']??''));?><tr>
      <td class="when" data-label="Finished"><?=h(str_replace('T',' ',substr((string)($row['finished_at']??''),0,19)))?></td>
      <td data-label="Result"><span class="badge b-<?=h($c==='completed'?$r:$c)?>"><?=h($c==='completed'?($resultLabels[$r]??'Unknown'):($completionLabels[$c]??'Unknown'))?></span></td>
      <td class="pathcell" data-label="Path"><span class="mono"><?=h((string)($row['scan_path']??'-'))?></span></td>
      <td class="num" data-label="Files"><?=number_format((int)($row['files_scanned']??0))?></td>
      <td class="num" data-label="Findings"><?=number_format((int)($row['findings_count']??0))?></td>
      <td class="num" data-label="Quarantined"><?=number_format((int)($row['quarantined_count']??0))?></td>
      <td class="num" data-label="Time"><?=number_format((int)($row['duration_seconds']??0))?>s</td>
      <td data-label="Report"><?php if($raw):?><a href="?report=<?=rawurlencode($raw)?>" target="_blank" rel="noopener">View log</a><?php else:?>&mdash;<?php endif;?></td>
    </tr><?php endforeach;?>
    </tbody></table></div>
  <?php endif;?>
  </div>
</details>

<details class="panel" id="p-exclusions"><summary>
  <svg class="pico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/></svg>
  Exclusions <span class="chip"><?=count($rules)?></span><span class="sub">paths never reported</span><span class="chev"></span></summary>
  <div class="pbody"><form method="post"><input type="hidden" name="action" value="save_exclusions"><input type="hidden" name="csrf" value="<?=h($csrf)?>">
  <label class="fld" for="exc">One path per line. Wildcards allowed, e.g. /home/site/cache/*</label>
  <textarea id="exc" name="exclusions" spellcheck="false"><?=h(implode(PHP_EOL,$rules))?></textarea>
  <div class="actions"><button class="btn btn-sm">Save Exclusions</button></div></form></div>
</details>

<details class="panel" id="p-settings" <?=(($_SERVER['REQUEST_METHOD']==='POST'&&in_array((string)($_POST['action']??''),['save_settings'],true))?'open':'')?>><summary>
  <svg class="pico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 7 19.4a1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H1a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 2.6 7a1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.7 1.7 0 0 0 7 2.6h.1A1.7 1.7 0 0 0 8.3 1V1a2 2 0 1 1 4 0" stroke-linejoin="round"/></svg>
  Scan Configuration<span class="sub">path, quarantine, execution</span><span class="chev"></span></summary>
  <div class="pbody">
  <form method="post"><input type="hidden" name="action" value="save_settings"><input type="hidden" name="csrf" value="<?=h($csrf)?>">
    <label class="fld" for="sp">Directory to scan</label>
    <input type="text" id="sp" name="scan_path" value="<?=h($configuredScanPath)?>" placeholder="<?=h($root)?>" spellcheck="false" autocomplete="off">
    <p class="hint">Absolute path. Leave empty to scan the folder the scanner sits in.<br>Allowed area: <?php foreach($allowedBases as $base):?><code><?=h($base)?></code> <?php endforeach;?></p>
    <label class="toggle"><input type="checkbox" class="check" name="auto_quarantine" value="1" <?=$autoQuarantine?'checked':''?>><span><b>Move infected files to quarantine automatically</b><span class="hint">Flagged files are moved during the scan. Legitimate plugins using eval or base64_decode can be flagged by mistake, so review the quarantine list after each scan.</span></span></label>
    <label class="toggle"><input type="checkbox" class="check" name="background_scan" value="1" <?=$backgroundScan?'checked':''?>><span><b>Run scans in the background</b><span class="hint">The browser returns immediately and cannot time out. If your host blocks background processes, leave this off.</span></span></label>
    <div class="actions"><button class="btn btn-sm">Save Settings</button></div>
  </form>
  <hr>
  <dl class="kv">
    <dt>Effective scan path</dt><dd><code><?=h($scanRoot)?></code></dd>
    <dt>Installed in</dt><dd><code><?=h($root)?></code></dd>
    <dt>Quarantine folder</dt><dd><code><?=h($quarantineDir)?></code></dd>
    <dt>Scanner engine</dt><dd><?=is_file($scanner)?'scanner.php found':'<strong>scanner.php missing</strong>'?></dd>
    <dt>Execution</dt><dd><?=$backgroundScan?'Background':'Foreground (page stays open)'?></dd>
    <dt>Memory</dt><dd>dashboard <?=h((string)ini_get('memory_limit'))?>, scanner <?=h(SCANNER_MEMORY_LIMIT)?><?php if(!empty($status['peak_memory'])):?>, last peak <?=h((string)$status['peak_memory'])?><?php endif;?></dd>
    <dt>Engine exit code</dt><dd><?=h((string)($status['exit_code']??'n/a'))?></dd>
  </dl>
  </div>
</details>

<details class="panel" id="p-diag"><summary>
  <svg class="pico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 12h4l2 6 4-14 2 8h6"/></svg>
  Server Diagnostics<span class="sub">why a scan will or will not start</span><span class="chev"></span></summary>
  <div class="pbody">
  <?php
  // Auto-detect and cache, so this panel shows the binary a scan would really use.
  $diagResolved = resolveWorkingPhp($phpCli, $configFile);
  $diagWorks = $diagResolved !== '';
  $diagPhp = $diagWorks ? $diagResolved : ($phpCli !== '' ? $phpCli : cliPhp());
  $diagLock = false;
  $probe = @fopen($lockFile, 'c');
  if ($probe) { $diagLock = flock($probe, LOCK_EX | LOCK_NB); if ($diagLock) flock($probe, LOCK_UN); fclose($probe); }
  $launchLogFile = $dataDir . DIRECTORY_SEPARATOR . 'launch.log';
  $launchOutput = is_file($launchLogFile) ? trim((string)@file_get_contents($launchLogFile)) : '';
  $okBadge = static fn(bool $ok, string $yes, string $no): string => '<span class="badge b-'.($ok?'clean':'failed').'">'.h($ok?$yes:$no).'</span>';
  ?>
  <dl class="kv diag">
    <dt>exec()</dt><dd><?=$okBadge(execAllowed(),'Available','Disabled')?></dd>
    <dt>shell_exec()</dt><dd><?=$okBadge(function_exists('shell_exec'),'Available','Disabled')?></dd>
    <dt>nohup</dt><dd><?=$okBadge((bool)$paths['nohup'],'Found','Not found')?></dd>
    <dt>PHP CLI in use</dt><dd><code><?=h($diagPhp)?></code></dd>
    <dt>CLI binary usable</dt><dd><?=$okBadge($diagWorks,'Yes','No - scans cannot run at all')?></dd>
    <dt>Detected platform</dt><dd><code><?=h(PHP_OS_FAMILY . ' / ' . PHP_SAPI)?></code></dd>
    <dt>File locking</dt><dd><?=$okBadge($diagLock,'Working','Busy or unsupported')?></dd>
    <dt>CLI candidates</dt><dd><code><?=h(implode(', ', phpCandidates()) ?: 'none found')?></code></dd>
  </dl>
  <?php if($launchOutput!==''):?><p class="hint" style="margin-top:12px"><b>Last launch output</b></p><pre><?=h(substr($launchOutput,0,2000))?></pre><?php endif;?>
  </div>
</details>

<?php renderFooter($installationId); ?>
</main>
<script>
var overlay=document.getElementById('overlay'),bar=document.getElementById('bar'),ptext=document.getElementById('ptext'),ppct=document.getElementById('ppct');
var watching=false,autoReload=true,backgroundMode=<?=$backgroundScan?'true':'false'?>;
function setBar(d){
  var p=d.percent>0?d.percent:3;
  bar.style.width=p+'%';
  ptext.textContent=d.percent>0?'Checking files':'Mapping files, please wait';
  ppct.textContent=d.percent>0?(d.percent+'% of '+Number(d.files).toLocaleString()+' files'):' ';
}
function poll(){
  fetch('?status=1',{cache:'no-store',credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
    if(d.running){ watching=true; overlay.classList.add('on'); setBar(d); setTimeout(poll,2500); }
    else if(watching&&autoReload){ bar.style.width='100%'; ptext.textContent='Finishing up'; ppct.textContent=' '; setTimeout(function(){location.replace(location.pathname);},900); }
    else if(!autoReload){ setTimeout(poll,2500); }
    else { overlay.classList.remove('on'); }
  }).catch(function(){ setTimeout(poll,5000); });
}
<?php if($running||$justStarted):?>watching=true;overlay.classList.add('on');poll();<?php endif;?>

/* theme toggle: auto by default, manual override remembered */
document.getElementById('themeBtn').addEventListener('click',function(){
  var root=document.documentElement;
  var cur=root.getAttribute('data-theme');
  if(!cur){cur=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}
  var next=cur==='dark'?'light':'dark';
  root.setAttribute('data-theme',next);
  try{localStorage.setItem('gts_theme',next);}catch(e){}
});

/* remember which panels are open */
(function(){
  var panels=document.querySelectorAll('details.panel');
  for(var i=0;i<panels.length;i++){(function(p){
    try{var v=localStorage.getItem('gts_panel_'+p.id);if(v==='1')p.open=true;else if(v==='0')p.open=false;}catch(e){}
    p.addEventListener('toggle',function(){try{localStorage.setItem('gts_panel_'+p.id,p.open?'1':'0');}catch(e){}});
  })(panels[i]);}
})();

function linkAll(master,cls){var m=document.getElementById(master);if(!m)return;var boxes=document.getElementsByClassName(cls);
  m.addEventListener('change',function(){for(var i=0;i<boxes.length;i++){boxes[i].checked=m.checked;}});
  for(var i=0;i<boxes.length;i++){boxes[i].addEventListener('change',function(){var all=boxes.length>0;for(var j=0;j<boxes.length;j++){if(!boxes[j].checked){all=false;break;}}m.checked=all;});}}
linkAll('allFindings','fchk');linkAll('allQuarantine','qchk');

var del=document.getElementById('deleteBtn');
if(del){del.addEventListener('click',function(e){var n=document.querySelectorAll('.qchk:checked').length;if(!n||!window.confirm('Permanently delete '+n+' file(s)? This cannot be undone.')){e.preventDefault();}});}

var form=document.getElementById('scanForm');
if(form){form.addEventListener('submit',function(e){
  overlay.classList.add('on');ptext.textContent='Starting scan';ppct.textContent=' ';
  var b=form.querySelector('button');b.disabled=true;b.textContent='Scanning...';
  watching=true;
  if(!backgroundMode&&window.fetch&&window.FormData){
    e.preventDefault();
    autoReload=false;
    setTimeout(poll,1200);
    var data=new FormData(form);data.append('ajax','1');
    fetch(location.pathname,{method:'POST',body:data,credentials:'same-origin'})
      .then(function(r){return r.text();})
      .then(function(){bar.style.width='100%';ptext.textContent='Finishing up';ppct.textContent=' ';setTimeout(function(){location.replace(location.pathname);},600);})
      .catch(function(){ptext.textContent='The scan stopped early - reloading to see what completed.';setTimeout(function(){location.replace(location.pathname);},2500);});
  }else{ setTimeout(poll,1200); }
});}

/* Stop scan: writes a cancel flag the scan loop checks, so partial results are kept. */
var stopBtn=document.getElementById('stopBtn'),stopNote=document.getElementById('stopnote');
if(stopBtn){stopBtn.addEventListener('click',function(){
  var msg = backgroundMode
    ? 'Stop the running scan? The scan process is ended and whatever it already reported is kept.'
    : 'Stop the running scan? The scan engine cannot be interrupted mid-file, so this takes effect when the current step finishes.';
  if(!window.confirm(msg))return;
  stopBtn.disabled=true;stopBtn.textContent='Stopping...';
  stopNote.textContent='Waiting for the scan to halt';
  autoReload=true;
  var d=new FormData();
  d.append('action','cancel_scan');
  d.append('csrf','<?=h($csrf)?>');
  d.append('ajax','1');
  fetch(location.pathname,{method:'POST',body:d,credentials:'same-origin'})
    .then(function(){setTimeout(poll,800);})
    .catch(function(){setTimeout(function(){location.replace(location.pathname);},1500);});
});}
</script>
</body></html>
