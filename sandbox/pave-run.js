#!/usr/bin/env node
/**
 * PAVE Secure Sandbox CLI
 * 
 * Execute Node.js scripts in a secure SpiderMonkey sandbox with permission controls.
 * 
 * Usage:
 *   pave-run script.js [args...]
 *   pave-run --allow-write=/tmp script.js
 *   pave-run --permissions
 *   pave-run --help
 */

var fs = require('fs');
var path = require('path');
var execSync = require('child_process').execSync;

// Import sandbox and permissions
var sandboxPath = path.join(__dirname, 'SandboxRunner.js');
var permissionPath = path.join(__dirname, 'permission.js');

var SandboxRunner = require(sandboxPath);
var Permission = require(permissionPath);

// ANSI colors (works in most terminals)
var colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

function c(color, text) {
  return colors[color] + text + colors.reset;
}

// Exit codes
var EXIT = {
  SUCCESS: 0,
  SCRIPT_ERROR: 1,
  PERMISSION_DENIED: 2,
  NOT_FOUND: 3,
  SANDBOX_FAILED: 4,
  NO_SPIDERMONKEY: 5,
  TIMEOUT: 126
};

// Find SpiderMonkey
function findSpiderMonkey() {
  var paths = [
    '/opt/homebrew/bin/js',      // macOS Homebrew
    '/usr/local/bin/js',          // Linux/macOS
    '/usr/bin/js78',              // iSH iOS
    '/usr/bin/js',                // System install
    '/usr/bin/js128',             // Newer versions
    '/usr/bin/js140'              // Even newer
  ];
  
  for (var i = 0; i < paths.length; i++) {
    if (fs.existsSync(paths[i])) return paths[i];
  }
  
  // Try which
  try {
    return execSync('which js 2>/dev/null', { encoding: 'utf8' }).trim();
  } catch (e) {
    return null;
  }
}

/**
 * Escape a string for safe use as a shell argument
 * Uses ANSI-C quoting ($'...') for strings with newlines/special chars
 */
function escapeShellArg(arg) {
  var str = String(arg);
  // If the string is simple (alphanumeric, dots, slashes, hyphens), no quoting needed
  if (/^[a-zA-Z0-9_./-]+$/.test(str)) {
    return str;
  }
  
  // If string contains newlines, tabs, or other control chars, use ANSI-C quoting $'...'
  if (/[\n\r\t]/.test(str)) {
    var escaped = str
      .replace(/\\/g, '\\\\')     // Backslash first
      .replace(/'/g, "\\'")       // Single quotes
      .replace(/\n/g, '\\n')      // Newlines
      .replace(/\r/g, '\\r')      // Carriage returns
      .replace(/\t/g, '\\t');     // Tabs
    return "$'" + escaped + "'";
  }
  
  // Use single quotes and escape any embedded single quotes
  return "'" + str.replace(/'/g, "'\\''") + "'";
}

// Parse command line arguments
function parseArgs(argv) {
  var args = {
    script: null,
    scriptArgs: [],
    permissions: {
      read: [],
      write: [],
      network: [],
      modules: []
    },
    dryRun: false,
    verbose: false,
    timeout: 60000,
    action: 'run',  // run, permissions, grant, revoke, help
    grantType: null,
    grantTarget: null,
    denyAll: false,
    allowAll: false
  };
  
  var i = 0;
  while (i < argv.length) {
    var arg = argv[i];
    
    if (arg === '--help' || arg === '-h') {
      args.action = 'help';
      return args;
    }
    
    if (arg === '--permissions' || arg === '-p') {
      args.action = 'permissions';
      return args;
    }
    
    if (arg === '--verbose' || arg === '-v') {
      args.verbose = true;
      i++;
      continue;
    }
    
    if (arg === '--dry-run') {
      args.dryRun = true;
      i++;
      continue;
    }
    
    if (arg === '--deny-all') {
      args.denyAll = true;
      i++;
      continue;
    }
    
    if (arg === '--allow-all') {
      args.allowAll = true;
      i++;
      continue;
    }
    
    if (arg.startsWith('--timeout=')) {
      args.timeout = parseInt(arg.split('=')[1], 10) || 60000;
      i++;
      continue;
    }
    
    if (arg.startsWith('--allow-read=')) {
      args.permissions.read.push(arg.split('=')[1]);
      i++;
      continue;
    }
    
    if (arg.startsWith('--allow-write=')) {
      args.permissions.write.push(arg.split('=')[1]);
      i++;
      continue;
    }
    
    if (arg.startsWith('--allow-network=')) {
      args.permissions.network.push(arg.split('=')[1]);
      i++;
      continue;
    }
    
    if (arg.startsWith('--allow-module=')) {
      args.permissions.modules.push(arg.split('=')[1]);
      i++;
      continue;
    }
    
    if (arg === '--grant') {
      args.action = 'grant';
      args.grantType = argv[i + 1];
      args.grantTarget = argv[i + 2];
      i += 3;
      continue;
    }
    
    if (arg === '--revoke') {
      args.action = 'revoke';
      args.grantType = argv[i + 1];
      args.grantTarget = argv[i + 2];
      i += 3;
      continue;
    }
    
    // Once script is found, ALL remaining args go to the script (including flags)
    if (!args.script) {
      // First non-pave-run-flag argument is the script
      if (!arg.startsWith('-')) {
        args.script = arg;
        // Collect all remaining args as script args
        args.scriptArgs = argv.slice(i + 1);
        break;  // Stop parsing - rest goes to script
      }
      // Unknown flag before script - skip it
      i++;
    } else {
      // Already have script - this shouldn't happen with the break above
      args.scriptArgs.push(arg);
      i++;
    }
  }
  
  return args;
}

// Show help
function showHelp() {
  console.log(c('bold', '\nPAVE Secure Sandbox CLI'));
  console.log(c('dim', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log('\nExecute Node.js scripts in a secure SpiderMonkey sandbox.\n');
  
  console.log(c('bold', 'Usage:'));
  console.log('  pave-run [options] <script.js> [script args...]\n');
  
  console.log(c('bold', 'Options:'));
  console.log('  --allow-read=<path>     Allow reading from path (glob supported)');
  console.log('  --allow-write=<path>    Allow writing to path (glob supported)');
  console.log('  --allow-network=<host>  Allow network access to host');
  console.log('  --allow-module=<name>   Allow specific module');
  console.log('  --deny-all              Start with no permissions');
  console.log('  --allow-all             Grant all permissions (dangerous!)');
  console.log('  --timeout=<ms>          Execution timeout (default: 60000)');
  console.log('  --dry-run               Show sandbox command without executing');
  console.log('  --verbose, -v           Show detailed execution info');
  console.log('  --permissions, -p       List current permissions');
  console.log('  --grant <type> <target> Grant a permission');
  console.log('  --revoke <type> <target> Revoke a permission');
  console.log('  --help, -h              Show this help\n');
  
  console.log(c('bold', 'Permission Types:'));
  console.log('  fs.read      Filesystem read access');
  console.log('  fs.write     Filesystem write access');
  console.log('  network      Network access');
  console.log('  module       Node.js module access\n');
  
  console.log(c('bold', 'Examples:'));
  console.log('  pave-run script.js');
  console.log('  pave-run --allow-write=/tmp script.js arg1 arg2');
  console.log('  pave-run --verbose --timeout=30000 script.js');
  console.log('  pave-run --grant fs.write /tmp/*');
  console.log('  pave-run --permissions\n');
  
  console.log(c('bold', 'Exit Codes:'));
  console.log('  0   Success');
  console.log('  1   Script error');
  console.log('  2   Permission denied');
  console.log('  3   Script not found');
  console.log('  4   Sandbox creation failed');
  console.log('  5   SpiderMonkey not found');
  console.log('  126 Timeout\n');
}

// Show permissions
function showPermissions() {
  var perms = Permission.listPermissions();
  
  console.log(c('bold', '\nCurrent Permissions'));
  console.log(c('dim', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
  
  // Handle nested filesystem structure
  var fsRead = perms.filesystem ? perms.filesystem.read : (perms['filesystem.read'] || []);
  var fsWrite = perms.filesystem ? perms.filesystem.write : (perms['filesystem.write'] || []);
  var network = perms.network || [];
  var modules = perms.modules || [];
  var system = perms.system || [];
  
  var types = [
    { values: fsRead, label: 'Filesystem Read' },
    { values: fsWrite, label: 'Filesystem Write' },
    { values: network, label: 'Network' },
    { values: modules, label: 'Modules' },
    { values: system, label: 'System Commands' }
  ];
  
  for (var i = 0; i < types.length; i++) {
    var t = types[i];
    var values = t.values || [];
    var status = values.length > 0 ? c('green', '✓') : c('red', '✗');
    var valueStr = values.length > 0 ? values.join(', ') : c('dim', '(none)');
    console.log('  ' + status + ' ' + c('bold', t.label) + ': ' + valueStr);
  }
  
  console.log('');
}

// Apply CLI permissions to the permission system
function applyCliPermissions(args) {
  // Reset if deny-all
  if (args.denyAll) {
    Permission.clearPermissions();
  }
  
  // Grant all if requested
  if (args.allowAll) {
    Permission.grantPermission('filesystem.read', '*');
    Permission.grantPermission('filesystem.write', '*');
    Permission.grantPermission('network', '*');
    Permission.grantPermission('modules', '*');
    Permission.grantPermission('system', '*');
  }
  
  // Apply specific permissions
  for (var i = 0; i < args.permissions.read.length; i++) {
    Permission.grantPermission('filesystem.read', args.permissions.read[i]);
  }
  
  for (var i = 0; i < args.permissions.write.length; i++) {
    Permission.grantPermission('filesystem.write', args.permissions.write[i]);
  }
  
  for (var i = 0; i < args.permissions.network.length; i++) {
    Permission.grantPermission('network', args.permissions.network[i]);
  }
  
  for (var i = 0; i < args.permissions.modules.length; i++) {
    Permission.grantPermission('modules', args.permissions.modules[i]);
  }
}

// Print header for verbose mode
function printHeader(scriptPath, args, analysis) {
  console.log('');
  console.log(c('cyan', '🛡️  ') + c('bold', 'PAVE Secure Sandbox'));
  console.log(c('dim', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(c('bold', 'Script: ') + scriptPath);
  
  if (args.scriptArgs.length > 0) {
    console.log(c('bold', 'Args: ') + args.scriptArgs.join(' '));
  }
  
  console.log('');
  console.log(c('bold', 'Permissions:'));
  var perms = Permission.listPermissions();
  
  // Handle nested filesystem structure
  var fsRead = perms.filesystem ? perms.filesystem.read : (perms['filesystem.read'] || []);
  var fsWrite = perms.filesystem ? perms.filesystem.write : (perms['filesystem.write'] || []);
  var network = perms.network || [];
  var modules = perms.modules || [];
  
  console.log('  ' + (fsRead.length > 0 ? c('green', '✓') : c('red', '✗')) + ' fs.read: ' + (fsRead.length > 0 ? fsRead.join(', ') : c('dim', '(none)')));
  console.log('  ' + (fsWrite.length > 0 ? c('green', '✓') : c('red', '✗')) + ' fs.write: ' + (fsWrite.length > 0 ? fsWrite.join(', ') : c('dim', '(none)')));
  console.log('  ' + (network.length > 0 ? c('green', '✓') : c('red', '✗')) + ' network: ' + (network.length > 0 ? network.join(', ') : c('dim', '(none)')));
  console.log('  ' + (modules.length > 0 ? c('green', '✓') : c('red', '✗')) + ' modules: ' + (modules.length > 0 ? modules.join(', ') : c('dim', '(none)')));
  
  console.log('');
  console.log(c('bold', 'Detected:'));
  console.log('  • requires: ' + (analysis.requires.length > 0 ? analysis.requires.join(', ') : c('dim', '(none)')));
  console.log('  • filesystem: ' + (analysis.usesFileSystem ? c('yellow', 'yes') : 'no'));
  console.log('  • network: ' + (analysis.usesNetwork ? c('yellow', 'yes') : 'no'));
  console.log('  • child_process: ' + (analysis.usesChildProcess ? c('red', 'yes (blocked)') : 'no'));
  console.log(c('dim', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log('');
}

// Run script in sandbox
function runScript(args) {
  var startTime = Date.now();
  
  // Find SpiderMonkey
  var jsPath = findSpiderMonkey();
  if (!jsPath) {
    console.error(c('red', 'Error: ') + 'SpiderMonkey (js) not found.');
    console.error('Install with: brew install spidermonkey');
    process.exit(EXIT.NO_SPIDERMONKEY);
  }
  
  // Resolve script path
  var scriptPath = path.resolve(args.script);
  if (!fs.existsSync(scriptPath)) {
    console.error(c('red', 'Error: ') + 'Script not found: ' + scriptPath);
    process.exit(EXIT.NOT_FOUND);
  }
  
  // Apply CLI permissions
  applyCliPermissions(args);
  
  // Read and analyze script
  var scriptContent = fs.readFileSync(scriptPath, 'utf8');
  var analysis = SandboxRunner.analyzeScript(scriptContent);
  
  // Print header in verbose mode
  if (args.verbose) {
    printHeader(scriptPath, args, analysis);
  }
  
  // Build command - escape each arg properly for shell
  var cmd = 'node ' + escapeShellArg(scriptPath);
  if (args.scriptArgs.length > 0) {
    cmd += ' ' + args.scriptArgs.map(escapeShellArg).join(' ');
  }
  
  // Transform to sandbox
  var result = SandboxRunner.transformToSandbox(cmd, 'cli');
  
  if (result.error) {
    console.error(c('red', 'Sandbox Error: ') + result.error);
    
    // Provide helpful suggestions
    if (result.error.includes('Permission denied')) {
      console.error('');
      console.error(c('yellow', 'Tip: ') + 'Grant permission with:');
      console.error('  pave-run --allow-write=/path ' + args.script);
    }
    
    process.exit(EXIT.SANDBOX_FAILED);
  }
  
  // Dry run - just show command
  if (args.dryRun) {
    console.log(c('bold', 'Dry Run - Would execute:'));
    console.log('  ' + result.command);
    console.log('');
    console.log(c('bold', 'Wrapper: ') + result.wrapperPath);
    console.log(c('bold', 'Session: ') + result.sessionId);
    
    // Clean up the wrapper since we won't use it
    SandboxRunner.cleanupWrapper(null, result.sessionId);
    process.exit(EXIT.SUCCESS);
  }
  
  // Execute
  try {
    var output = execSync(result.command, {
      encoding: 'utf8',
      timeout: args.timeout,
      stdio: ['inherit', 'pipe', 'pipe'],
      maxBuffer: 10 * 1024 * 1024
    });
    
    console.log(output);
    
    // Read exit result
    var exitResult = SandboxRunner.readResult(result.sessionId);
    var exitCode = exitResult ? exitResult.exit : 0;
    
    if (args.verbose) {
      var duration = Date.now() - startTime;
      console.log(c('dim', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
      console.log(c('green', '✓') + ' Completed (exit: ' + exitCode + ') in ' + duration + 'ms');
    }
    
    process.exit(exitCode === 0 ? EXIT.SUCCESS : EXIT.SCRIPT_ERROR);
    
  } catch (e) {
    if (e.killed) {
      console.error(c('red', 'Timeout: ') + 'Script exceeded ' + args.timeout + 'ms');
      process.exit(EXIT.TIMEOUT);
    }
    
    // Show stderr if available
    if (e.stderr) {
      console.error(e.stderr);
    }
    
    // Check for permission errors in output
    if (e.stdout && e.stdout.includes('Permission denied')) {
      console.error('');
      console.error(c('yellow', 'Tip: ') + 'Grant permission with --allow-write or --allow-network');
      process.exit(EXIT.PERMISSION_DENIED);
    }
    
    console.error(c('red', 'Error: ') + e.message);
    process.exit(EXIT.SCRIPT_ERROR);
    
  } finally {
    // Always clean up
    SandboxRunner.cleanupWrapper(null, result.sessionId);
  }
}

// Grant permission
function grantPermission(type, target) {
  if (!type || !target) {
    console.error(c('red', 'Error: ') + 'Usage: pave-run --grant <type> <target>');
    console.error('Types: fs.read, fs.write, network, module');
    process.exit(1);
  }
  
  // Normalize type
  var normalizedType = type;
  if (type === 'fs.read') normalizedType = 'filesystem.read';
  if (type === 'fs.write') normalizedType = 'filesystem.write';
  if (type === 'module') normalizedType = 'modules';
  
  Permission.grantPermission(normalizedType, target);
  console.log(c('green', '✓') + ' Granted ' + type + ': ' + target);
}

// Revoke permission
function revokePermission(type, target) {
  if (!type || !target) {
    console.error(c('red', 'Error: ') + 'Usage: pave-run --revoke <type> <target>');
    process.exit(1);
  }
  
  // Normalize type
  var normalizedType = type;
  if (type === 'fs.read') normalizedType = 'filesystem.read';
  if (type === 'fs.write') normalizedType = 'filesystem.write';
  if (type === 'module') normalizedType = 'modules';
  
  Permission.revokePermission(normalizedType, target);
  console.log(c('green', '✓') + ' Revoked ' + type + ': ' + target);
}

// Main
function main() {
  var args = parseArgs(process.argv.slice(2));
  
  // Set log level based on verbose flag
  // 0 = silent, 1 = errors/warnings only, 2 = normal, 3 = verbose/debug
  // Default to 0 (silent) to avoid leaking token/permission info to LLM context
  Permission.setLogLevel(args.verbose ? 3 : 0);
  
  switch (args.action) {
    case 'help':
      showHelp();
      process.exit(EXIT.SUCCESS);
      break;
      
    case 'permissions':
      showPermissions();
      process.exit(EXIT.SUCCESS);
      break;
      
    case 'grant':
      grantPermission(args.grantType, args.grantTarget);
      process.exit(EXIT.SUCCESS);
      break;
      
    case 'revoke':
      revokePermission(args.grantType, args.grantTarget);
      process.exit(EXIT.SUCCESS);
      break;
      
    case 'run':
      if (!args.script) {
        console.error(c('red', 'Error: ') + 'No script specified.');
        console.error('Usage: pave-run [options] <script.js>');
        console.error('Try: pave-run --help');
        process.exit(1);
      }
      runScript(args);
      break;
      
    default:
      showHelp();
      process.exit(1);
  }
}

main();
