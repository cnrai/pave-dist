/**
 * Sandbox Runner for Node.js Scripts
 * 
 * Uses SpiderMonkey's newGlobal() for compartment isolation:
 * 1. Creates isolated sandbox with newGlobal({ newCompartment: true })
 * 2. Deletes all dangerous globals (os, read, load, etc.)
 * 3. Exposes only __ipc__ bridge function for controlled access
 * 4. Defines mock Node.js APIs inside sandbox using sandbox.eval()
 * 5. User code runs in sandbox - cannot escape to parent scope
 * 
 * Security model:
 * - User code can only access __ipc__ bridge
 * - __ipc__ checks permissions before executing operations
 * - Constructor escape returns sandbox global (no parent access)
 */

const fs = require('fs');
const path = require('path');
const { 
  checkPermission, 
  listPermissions,
  hasToken,
  listTokens,
  getTokenConfig,
  isTokenDomainAllowed,
  logTokenUsage,
  _buildTokenInjection,
  _getRefreshTokenValue,
  _getOAuthClientCredentials,
  _buildOAuthRefreshConfig,
  loadPermissions,
  getLogLevel
} = require('./permission');

// Logging helpers that respect log level
function _logDebug(...args) {
  if (getLogLevel() >= 3) console.log(...args);
}
function _logInfo(...args) {
  if (getLogLevel() >= 2) console.log(...args);
}
function _logError(...args) {
  if (getLogLevel() >= 1) console.error(...args);
}

// Sandbox session directory
const SANDBOX_DIR = '/tmp/pave_sandbox';

/**
 * Ensure sandbox directory exists
 */
function ensureSandboxDir() {
  if (!fs.existsSync(SANDBOX_DIR)) {
    fs.mkdirSync(SANDBOX_DIR, { recursive: true });
  }
}

/**
 * Get paths for a sandbox session
 */
function getSessionPaths(sessionId) {
  return {
    wrapper: path.join(SANDBOX_DIR, `${sessionId}_wrapper.js`),
    sandboxApis: path.join(SANDBOX_DIR, `${sessionId}_apis.js`),
    result: path.join(SANDBOX_DIR, `${sessionId}_result.json`)
  };
}

/**
 * Transform a Node.js command to run in SpiderMonkey sandbox
 */
function transformToSandbox(command, toolId) {
  // Reload permissions from disk before each sandbox execution
  // This ensures changes to permissions.json are reflected without server restart
  loadPermissions();
  
  _logDebug(`[SANDBOX:${toolId}] Analyzing command: ${command}`);
  
  const nodeMatch = command.match(/\bnode\s+(.+)/);
  if (!nodeMatch) {
    return { sandboxed: false, command, wrapperPath: null, sessionId: null };
  }
  
  const fullArgs = nodeMatch[1].trim();
  const args = parseArgs(fullArgs);
  
  let scriptPath = null;
  let scriptArgs = [];
  let foundScript = false;
  
  for (const arg of args) {
    if (!foundScript && !arg.startsWith('--')) {
      scriptPath = arg;
      foundScript = true;
    } else if (foundScript) {
      scriptArgs.push(arg);
    }
  }
  
  if (!scriptPath) {
    return { sandboxed: false, command, wrapperPath: null, sessionId: null };
  }
  
  const resolvedPath = path.isAbsolute(scriptPath) ? scriptPath : path.resolve(scriptPath);
  if (!fs.existsSync(resolvedPath)) {
    return { 
      sandboxed: false, command, wrapperPath: null, sessionId: null, 
      error: `Script not found: ${scriptPath}` 
    };
  }
  
  const scriptContent = fs.readFileSync(resolvedPath, 'utf8');
  const analysis = analyzeScript(scriptContent);
  _logDebug(`[SANDBOX:${toolId}] Analysis:`, JSON.stringify(analysis));
  
  // Check module permissions
  const permissionIssues = [];
  for (const mod of analysis.requires) {
    if (!checkPermission('module', mod)) {
      permissionIssues.push(`Module '${mod}' not permitted`);
    }
  }
  
  if (permissionIssues.length > 0) {
    return {
      sandboxed: false, command, wrapperPath: null, sessionId: null,
      error: `Permission denied:\n${permissionIssues.join('\n')}`
    };
  }
  
  ensureSandboxDir();
  const sessionId = `${toolId}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
  const paths = getSessionPaths(sessionId);
  
  try {
    const perms = listPermissions();
    createSandboxWrapper(paths, resolvedPath, scriptContent, scriptArgs, perms, sessionId);
    _logDebug(`[SANDBOX:${toolId}] Created wrapper: ${paths.wrapper}`);
    
    return {
      sandboxed: true,
      command: `js ${paths.wrapper}`,
      wrapperPath: paths.wrapper,
      sessionId,
      originalScript: scriptPath
    };
  } catch (error) {
    _logError(`[SANDBOX:${toolId}] Error: ${error.message}`);
    return {
      sandboxed: false, command, wrapperPath: null, sessionId: null,
      error: `Failed to create sandbox: ${error.message}`
    };
  }
}

/**
 * Parse a shell command string into arguments
 * Handles single quotes, double quotes, ANSI-C quoting ($'...'), and the shell escape pattern '\'' for embedded single quotes
 * Example: 'foo'\''bar' becomes foo'bar
 * Example: $'line1\nline2' becomes "line1\nline2" (with actual newline)
 */
function parseArgs(str) {
  const args = [];
  let current = '';
  let i = 0;
  
  while (i < str.length) {
    const ch = str[i];
    
    // Check for ANSI-C quoting: $'...'
    if (ch === '$' && str[i + 1] === "'") {
      i += 2; // Skip $'
      while (i < str.length && str[i] !== "'") {
        if (str[i] === '\\' && i + 1 < str.length) {
          // Handle escape sequences in ANSI-C quoting
          i++;
          const escapeChar = str[i];
          switch (escapeChar) {
            case 'n': current += '\n'; break;
            case 'r': current += '\r'; break;
            case 't': current += '\t'; break;
            case '\\': current += '\\'; break;
            case "'": current += "'"; break;
            case '"': current += '"'; break;
            case '0': current += '\0'; break;
            default: current += escapeChar; break;
          }
        } else {
          current += str[i];
        }
        i++;
      }
      i++; // Skip closing quote
      
    } else if (ch === "'") {
      // Check for shell escape pattern: '\'' (end quote, escaped quote, start quote)
      if (str.slice(i, i + 4) === "'\\''" && current.length > 0) {
        // This is an escaped single quote within a single-quoted string
        current += "'";
        i += 4;
        continue;
      }
      
      // Start of single-quoted string
      i++;
      while (i < str.length && str[i] !== "'") {
        current += str[i];
        i++;
      }
      i++; // Skip closing quote
      
    } else if (ch === '"') {
      // Double-quoted string
      i++;
      while (i < str.length && str[i] !== '"') {
        if (str[i] === '\\' && i + 1 < str.length) {
          // Handle escape sequences in double quotes
          i++;
          current += str[i];
        } else {
          current += str[i];
        }
        i++;
      }
      i++; // Skip closing quote
      
    } else if (ch === '\\' && i + 1 < str.length) {
      // Escaped character outside quotes
      i++;
      current += str[i];
      i++;
      
    } else if (ch === ' ' || ch === '\t') {
      // Whitespace - end of argument
      if (current) {
        args.push(current);
        current = '';
      }
      i++;
      
    } else {
      // Regular character
      current += ch;
      i++;
    }
  }
  
  if (current) {
    args.push(current);
  }
  
  return args;
}

function analyzeScript(content) {
  const requires = new Set();
  const imports = new Set();
  let usesNetwork = false;
  let usesFileSystem = false;
  let usesChildProcess = false;
  
  const requirePattern = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  let match;
  while ((match = requirePattern.exec(content)) !== null) {
    const mod = match[1];
    if (!mod.startsWith('.') && !mod.startsWith('/')) requires.add(mod);
  }
  
  const importPattern = /import\s+.*?\s+from\s+['"]([^'"]+)['"]/g;
  while ((match = importPattern.exec(content)) !== null) {
    const mod = match[1];
    if (!mod.startsWith('.') && !mod.startsWith('/')) imports.add(mod);
  }
  
  const networkMods = ['http', 'https', 'fetch', 'axios', 'request', 'net', 'dns', 'dgram'];
  for (const mod of networkMods) {
    if (requires.has(mod) || imports.has(mod)) usesNetwork = true;
  }
  
  if (requires.has('fs') || requires.has('fs/promises') || imports.has('fs')) usesFileSystem = true;
  if (requires.has('child_process') || imports.has('child_process')) usesChildProcess = true;
  
  return { requires: Array.from(requires), imports: Array.from(imports), usesNetwork, usesFileSystem, usesChildProcess };
}

/**
 * Create sandbox wrapper using separate files to avoid escaping issues
 */
function createSandboxWrapper(paths, scriptPath, scriptContent, scriptArgs, perms, sessionId) {
  const scriptDir = path.dirname(scriptPath);
  const scriptName = path.basename(scriptPath);
  
  // Build token injection configs (pre-compute for IPC bridge)
  // This includes the actual token values, injected into the trusted wrapper
  const tokenInjections = {};
  const tokenRefreshConfigs = {};
  const tokenNames = listTokens();
  for (const name of tokenNames) {
    const injection = _buildTokenInjection(name);
    if (injection) {
      tokenInjections[name] = injection;
    }
    // Also build refresh config for OAuth tokens
    const refreshConfig = _buildOAuthRefreshConfig(name);
    if (refreshConfig) {
      tokenRefreshConfigs[name] = refreshConfig;
    }
  }
  
  // Write the sandbox APIs file (loaded by sandbox.eval via file read)
  const modulesPermission = perms.modules || ['*'];
  const apisContent = generateSandboxApis(scriptPath, scriptArgs, scriptDir, tokenNames, modulesPermission);
  fs.writeFileSync(paths.sandboxApis, apisContent);
  
  // Write the main wrapper
  const logLevel = getLogLevel();
  const wrapper = `// PAVE Sandbox Wrapper
// Script: ${scriptPath}
// Session: ${sessionId}

// ============================================================
// PHASE 1: Permissions
// ============================================================
var __perms = {
  fsRead: ${JSON.stringify(perms.filesystem?.read || perms['filesystem.read'] || ['*'])},
  fsWrite: ${JSON.stringify(perms.filesystem?.write || perms['filesystem.write'] || [])},
  network: ${JSON.stringify(perms.network || [])},
  modules: ${JSON.stringify(perms.modules || ['*'])},
  system: ${JSON.stringify(perms.system || [])}
};

// Token injection configs (token values are here in trusted wrapper, NOT in sandbox)
var __tokenInjections = ${JSON.stringify(tokenInjections)};
var __tokenRefreshConfigs = ${JSON.stringify(tokenRefreshConfigs)};
var __tokenNames = ${JSON.stringify(tokenNames)};
var __sessionId = "${sessionId}";
var __logLevel = ${logLevel}; // 0=silent, 1=errors, 2=normal, 3=verbose

// SECURITY: Normalize filesystem path to prevent traversal attacks
// Resolves '..' and '.' segments to prevent escaping allowed directories
function __normalizePath(p) {
  if (!p || typeof p !== 'string') return p;
  
  // Split path into segments
  var segments = p.split('/');
  var result = [];
  var isAbsolute = p.charAt(0) === '/';
  
  for (var i = 0; i < segments.length; i++) {
    var seg = segments[i];
    if (seg === '' || seg === '.') {
      // Skip empty segments and current directory markers
      continue;
    } else if (seg === '..') {
      // Go up one directory, but don't go above root
      if (result.length > 0 && result[result.length - 1] !== '..') {
        result.pop();
      } else if (!isAbsolute) {
        result.push('..');
      }
      // For absolute paths, '..' at root just stays at root
    } else {
      result.push(seg);
    }
  }
  
  var normalized = result.join('/');
  if (isAbsolute) {
    normalized = '/' + normalized;
  }
  return normalized || (isAbsolute ? '/' : '.');
}

// UTF-8 encode a JavaScript string to a Uint8Array
// This is needed because charCodeAt() returns code points, not bytes
// and multi-byte characters (emojis, etc.) need proper UTF-8 encoding
function __utf8Encode(str) {
  var bytes = [];
  for (var i = 0; i < str.length; i++) {
    var code = str.charCodeAt(i);
    // Handle surrogate pairs (emoji and other supplementary characters)
    if (code >= 0xD800 && code <= 0xDBFF && i + 1 < str.length) {
      var next = str.charCodeAt(i + 1);
      if (next >= 0xDC00 && next <= 0xDFFF) {
        // Combine surrogate pair into full code point
        code = 0x10000 + ((code - 0xD800) << 10) + (next - 0xDC00);
        i++; // Skip the low surrogate
      }
    }
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xC0 | (code >> 6));
      bytes.push(0x80 | (code & 0x3F));
    } else if (code < 0x10000) {
      bytes.push(0xE0 | (code >> 12));
      bytes.push(0x80 | ((code >> 6) & 0x3F));
      bytes.push(0x80 | (code & 0x3F));
    } else {
      bytes.push(0xF0 | (code >> 18));
      bytes.push(0x80 | ((code >> 12) & 0x3F));
      bytes.push(0x80 | ((code >> 6) & 0x3F));
      bytes.push(0x80 | (code & 0x3F));
    }
  }
  return new Uint8Array(bytes);
}

function __checkPerm(type, resource) {
  var list;
  if (type === 'fs.read') list = __perms.fsRead;
  else if (type === 'fs.write') list = __perms.fsWrite;
  else if (type === 'network') list = __perms.network;
  else if (type === 'system') list = __perms.system;
  else return false;
  
  if (!list || list.length === 0) return false;
  if (list.indexOf('*') >= 0) return true;
  
  // Normalize hostname for network checks (remove www. prefix)
  var normalizedResource = resource;
  if (type === 'network') {
    normalizedResource = resource.toLowerCase().replace(/^www\\./, '');
  } else if (type === 'fs.read' || type === 'fs.write') {
    // SECURITY: Normalize filesystem paths to prevent traversal attacks
    normalizedResource = __normalizePath(resource);
  }
  
  for (var i = 0; i < list.length; i++) {
    var pattern = list[i];
    // Also normalize the pattern for network
    if (type === 'network') {
      pattern = pattern.toLowerCase().replace(/^www\\./, '');
    }
    if (pattern === normalizedResource) return true;
    if (pattern === resource) return true;
    if (pattern.endsWith('/*')) {
      // SECURITY: Normalize the pattern base and check with path separator
      var patternBase = __normalizePath(pattern.slice(0, -2));
      if (normalizedResource === patternBase || normalizedResource.indexOf(patternBase + '/') === 0) {
        return true;
      }
    }
  }
  return false;
}

// Check if hostname is allowed for a token
function __isTokenDomainAllowed(tokenName, hostname) {
  var injection = __tokenInjections[tokenName];
  if (!injection || !injection.domains) return false;
  
  var normalizedHost = hostname.toLowerCase().replace(/^www\\./, '');
  
  for (var i = 0; i < injection.domains.length; i++) {
    var allowed = injection.domains[i];
    if (normalizedHost === allowed) return true;
    // Allow subdomains
    if (normalizedHost.length > allowed.length && 
        normalizedHost.slice(-(allowed.length + 1)) === '.' + allowed) {
      return true;
    }
  }
  return false;
}

// Log token usage (print to stdout for capture by parent process)
// Only logs if __logLevel >= 2 (normal) to avoid leaking to LLM context
function __logTokenUsage(tokenName, domain, method, urlPath) {
  if (__logLevel >= 2) {
    var timestamp = new Date().toISOString();
    print('[TOKEN AUDIT] ' + timestamp + ' | ' + tokenName + ' | ' + domain + ' | ' + method + ' ' + urlPath + ' | session:' + __sessionId);
  }
}

// Refresh OAuth token and update injection config
function __refreshOAuthToken(tokenName) {
  var refreshConfig = __tokenRefreshConfigs[tokenName];
  if (!refreshConfig || !refreshConfig.refreshUrl || !refreshConfig.refreshToken) {
    return { success: false, error: 'No refresh config available' };
  }
  
  // Build refresh request body
  var bodyParts = ['grant_type=refresh_token'];
  bodyParts.push('refresh_token=' + encodeURIComponent(refreshConfig.refreshToken));
  if (refreshConfig.clientId) {
    bodyParts.push('client_id=' + encodeURIComponent(refreshConfig.clientId));
  }
  if (refreshConfig.clientSecret) {
    bodyParts.push('client_secret=' + encodeURIComponent(refreshConfig.clientSecret));
  }
  var bodyStr = bodyParts.join('&');
  
  // Make refresh request - write body to temp file to avoid shell escaping issues
  var tmpFile = '/tmp/pave_refresh_' + Date.now() + '_' + Math.random().toString(36).substr(2,6) + '.txt';
  var bodyFile = tmpFile + '.body';
  var bodyArr = __utf8Encode(bodyStr);
  os.file.writeTypedArrayToFile(bodyFile, bodyArr);
  
  var curlCmd = "curl -s -S -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d @" + 
                bodyFile + " -o " + tmpFile + " '" + 
                refreshConfig.refreshUrl.replace(/'/g, "'\\''") + "' 2>&1";
  
  try {
    var exitCode = os.system(curlCmd);
    var responseBody = '';
    try { responseBody = os.file.readFile(tmpFile); } catch(e) {}
    try { os.system('rm -f ' + tmpFile + ' ' + bodyFile + ' 2>/dev/null'); } catch(e) {}
    
    if (exitCode !== 0 || !responseBody) {
      return { success: false, error: 'Refresh request failed' };
    }
    
    var response = JSON.parse(responseBody);
    
    if (response.access_token) {
      // Update the injection config with new token, or create one if it doesn't exist
      var injection = __tokenInjections[tokenName];
      if (injection) {
        // Update existing injection
        var format = injection.value.indexOf('Bearer ') === 0 ? 'Bearer {token}' :
                     injection.value.indexOf('token ') === 0 ? 'token {token}' : '{token}';
        injection.value = format.replace('{token}', response.access_token);
      } else {
        // Create new injection for this token (first-time refresh)
        // Get domain info from refresh config
        var domains = [];
        if (refreshConfig.domains) {
          domains = refreshConfig.domains;
        }
        __tokenInjections[tokenName] = {
          type: 'header',
          name: 'Authorization',
          value: 'Bearer ' + response.access_token,
          domains: domains
        };
      }
      
      // Update refresh token if provided
      if (response.refresh_token) {
        refreshConfig.refreshToken = response.refresh_token;
      }
      
      __logTokenUsage(tokenName, 'oauth-refresh', 'POST', refreshConfig.refreshUrl);
      print('[TOKEN] Successfully refreshed OAuth token: ' + tokenName);
      
      return { success: true, newToken: response.access_token };
    } else {
      return { success: false, error: response.error_description || response.error || 'Unknown error' };
    }
  } catch(e) {
    try { os.system('rm -f ' + tmpFile + ' 2>/dev/null'); } catch(ex) {}
    return { success: false, error: e.toString() };
  }
}

// ============================================================
// PHASE 2: Create Sandbox
// ============================================================
var sandbox = newGlobal({ newCompartment: true });

// Delete dangerous globals
var __del = [
  "os", "read", "snarf", "readline", "readlineBuf",
  "load", "loadRelativeToScript", "readRelativeToScript",
  "run", "putstr", "evaluate", "evalcx", "parse", "syntaxParse",
  "compileToStencil", "evalStencil", "offThreadCompileToStencil",
  "quit", "terminate", "timeout", "sleep", "interruptIf",
  "newGlobal", "nukeAllCCWs", "nukeCCW",
  "dumpHeap", "dumpStencil", "dumpScopeChain",
  "gc", "gcparam", "minorgc", "gcslice",
  "redirect", "redirectErr", "serialize", "deserialize"
];
for (var i = 0; i < __del.length; i++) {
  try { delete sandbox[__del[i]]; } catch(e) {}
}

// ============================================================
// PHASE 3: IPC Bridge
// ============================================================
sandbox.__ipc__ = function(cmd, a1, a2) {
  if (cmd === 'print') { print(a1); return true; }
  if (cmd === 'error') { print('[ERROR] ' + a1); return true; }
  
  if (cmd === 'fs.read') {
    if (!__checkPerm('fs.read', a1)) return { err: 'Permission denied: ' + a1 };
    try { return { data: os.file.readFile(a1) }; }
    catch(e) { return { err: e.toString() }; }
  }
  
  if (cmd === 'fs.readdir') {
    if (!__checkPerm('fs.read', a1)) return { err: 'Permission denied: ' + a1 };
    try {
      var f = os.file.listDir(a1).filter(function(x) { return x !== '.' && x !== '..'; });
      return { data: f };
    } catch(e) { return { err: e.toString() }; }
  }
  
  if (cmd === 'fs.exists') {
    // SECURITY: Check fs.read permission before probing file existence
    if (!__checkPerm('fs.read', a1)) return { err: 'Permission denied: ' + a1 };
    try { os.file.readFile(a1); return { exists: true }; }
    catch(e) { return { exists: false }; }
  }
  
  if (cmd === 'fs.write') {
    if (!__checkPerm('fs.write', a1)) return { err: 'Permission denied: ' + a1 };
    try {
      var arr = new Uint8Array(a2.length);
      for (var j = 0; j < a2.length; j++) arr[j] = a2.charCodeAt(j);
      os.file.writeTypedArrayToFile(a1, arr);
      return { ok: true };
    } catch(e) { return { err: e.toString() }; }
  }
  
  if (cmd === 'env.get') {
    try { return { val: os.getenv(a1) || '' }; }
    catch(e) { return { val: '' }; }
  }
  
  if (cmd === 'fetch') {
    // a1 = url, a2 = options (JSON string)
    var url = a1;
    var opts = a2 ? JSON.parse(a2) : {};
    
    // Extract hostname for permission check
    var hostMatch = url.match(/^https?:\\/\\/([^\\/]+)/);
    var hostname = hostMatch ? hostMatch[1].replace(/:\\d+$/, '') : '';
    
    if (!__checkPerm('network', hostname) && !__checkPerm('network', '*')) {
      return { err: 'Network permission denied for: ' + hostname };
    }
    
    // Build curl command
    var tmpFile = '/tmp/pave_fetch_' + Date.now() + '_' + Math.random().toString(36).substr(2,6) + '.txt';
    var headerFile = tmpFile + '.headers';
    var curlCmd = 'curl -s -S';
    
    // Add method
    if (opts.method && opts.method !== 'GET') {
      curlCmd += ' -X ' + opts.method;
    }
    
    // Add headers
    if (opts.headers) {
      var hdrs = opts.headers;
      for (var hk in hdrs) {
        if (hdrs.hasOwnProperty(hk)) {
          curlCmd += " -H '" + hk + ': ' + hdrs[hk].replace(/'/g, "'\\''") + "'";
        }
      }
    }
    
    // Add body - write to temp file to avoid shell escaping issues with complex content
    // Use --data-binary to preserve newlines and send content exactly as-is
    var bodyFile = null;
    if (opts.body) {
      bodyFile = tmpFile + '.body';
      var arr = __utf8Encode(opts.body);
      os.file.writeTypedArrayToFile(bodyFile, arr);
      curlCmd += ' --data-binary @' + bodyFile;
    }
    
    // Add timeout (default 30s)
    var timeout = opts.timeout ? Math.ceil(opts.timeout / 1000) : 30;
    curlCmd += ' --max-time ' + timeout;
    
    // Capture response headers
    curlCmd += ' -D ' + headerFile;
    
    // Output to file and add URL
    curlCmd += " -o " + tmpFile + " '" + url.replace(/'/g, "'\\''") + "' 2>&1";
    
    try {
      var exitCode = os.system(curlCmd);
      
      // Read response body
      var body = '';
      try { body = os.file.readFile(tmpFile); } catch(e) {}
      
      // Read response headers
      var headersRaw = '';
      try { headersRaw = os.file.readFile(headerFile); } catch(e) {}
      
      // Parse status from headers
      var status = 0;
      var statusMatch = headersRaw.match(/HTTP\\/[0-9.]+ (\\d+)/);
      if (statusMatch) status = parseInt(statusMatch[1], 10);
      
      // Cleanup temp files
      var cleanupFiles = tmpFile + ' ' + headerFile;
      if (bodyFile) cleanupFiles += ' ' + bodyFile;
      try { os.system('rm -f ' + cleanupFiles + ' 2>/dev/null'); } catch(e) {}
      
      if (exitCode !== 0 && !body) {
        return { err: 'Fetch failed with exit code ' + exitCode };
      }
      
      return { 
        ok: status >= 200 && status < 300,
        status: status || 200,
        body: body,
        headers: headersRaw
      };
    } catch(e) {
      // Cleanup on error
      var cleanupFilesErr = tmpFile + ' ' + headerFile;
      if (bodyFile) cleanupFilesErr += ' ' + bodyFile;
      try { os.system('rm -f ' + cleanupFilesErr + ' 2>/dev/null'); } catch(ex) {}
      return { err: e.toString() };
    }
  }
  
  // ============================================================
  // TOKEN IPC HANDLERS
  // ============================================================
  
  if (cmd === 'token.list') {
    // Return list of available token names (no values)
    return { tokens: __tokenNames };
  }
  
  if (cmd === 'token.has') {
    // a1 = tokenName
    var tokenName = a1;
    // Token exists if we have an injection OR if it's an OAuth token that can be refreshed
    var exists = (__tokenInjections.hasOwnProperty(tokenName) && __tokenInjections[tokenName] !== null) ||
                 __tokenRefreshConfigs.hasOwnProperty(tokenName);
    return { has: exists };
  }
  
  if (cmd === 'token.fetch') {
    // a1 = tokenName, a2 = JSON string { url, method, headers, body, timeout }
    var tokenName = a1;
    var reqData = a2 ? JSON.parse(a2) : {};
    var url = reqData.url;
    var opts = reqData;
    
    // Validate token exists - for OAuth tokens, try to refresh if no access token yet
    var injection = __tokenInjections[tokenName];
    if (!injection) {
      // Check if this is an OAuth token that can be refreshed
      if (__tokenRefreshConfigs[tokenName]) {
        print('[TOKEN] No access token for ' + tokenName + ', attempting OAuth refresh...');
        var refreshResult = __refreshOAuthToken(tokenName);
        if (refreshResult.success) {
          injection = __tokenInjections[tokenName];
        } else {
          print('[TOKEN] OAuth refresh failed: ' + refreshResult.error);
          return { err: 'OAuth token refresh failed: ' + refreshResult.error };
        }
      }
      
      // If still no injection, token truly doesn't exist
      if (!injection) {
        return { err: 'Token not found: ' + tokenName };
      }
    }
    
    // Extract hostname from URL
    var hostMatch = url.match(/^https?:\\/\\/([^\\/]+)/);
    if (!hostMatch) {
      return { err: 'Invalid URL format' };
    }
    var hostname = hostMatch[1].replace(/:\\d+$/, '');
    
    // Validate domain is allowed for this token
    if (!__isTokenDomainAllowed(tokenName, hostname)) {
      return { err: 'Token \\'' + tokenName + '\\' not authorized for domain: ' + hostname };
    }
    
    // Extract path for audit logging
    var urlPath = '/';
    try {
      var pathMatch = url.match(/^https?:\\/\\/[^\\/]+(\\/[^?#]*)?/);
      if (pathMatch && pathMatch[1]) urlPath = pathMatch[1];
    } catch(e) {}
    
    // Helper function to execute the request with current token
    function __executeTokenRequest(currentInjection) {
      var tmpFile = '/tmp/pave_tokenfetch_' + Date.now() + '_' + Math.random().toString(36).substr(2,6) + '.txt';
      var headerFile = tmpFile + '.headers';
      var curlCmd = 'curl -s -S';
      
      // Add method
      if (opts.method && opts.method !== 'GET') {
        curlCmd += ' -X ' + opts.method;
      }
      
      // Inject token based on placement type
      var finalUrl = url;
      if (currentInjection.type === 'header') {
        curlCmd += " -H '" + currentInjection.name + ': ' + currentInjection.value.replace(/'/g, "'\\''") + "'";
      } else if (currentInjection.type === 'query') {
        var sep = url.indexOf('?') >= 0 ? '&' : '?';
        finalUrl = url + sep + encodeURIComponent(currentInjection.name) + '=' + encodeURIComponent(currentInjection.value);
      }
      
      // Add user headers
      if (opts.headers) {
        var hdrs = opts.headers;
        for (var hk in hdrs) {
          if (hdrs.hasOwnProperty(hk)) {
            if (currentInjection.type === 'header' && hk.toLowerCase() === currentInjection.name.toLowerCase()) {
              continue;
            }
            curlCmd += " -H '" + hk + ': ' + hdrs[hk].replace(/'/g, "'\\''") + "'";
          }
        }
      }
      
      // Add body - write to temp file to avoid shell escaping issues with complex content
      // Use --data-binary to preserve newlines and send content exactly as-is
      var bodyFile = null;
      if (opts.body) {
        bodyFile = tmpFile + '.body';
        var arr = __utf8Encode(opts.body);
        os.file.writeTypedArrayToFile(bodyFile, arr);
        curlCmd += ' --data-binary @' + bodyFile;
      }
      
      // Add timeout
      var timeout = opts.timeout ? Math.ceil(opts.timeout / 1000) : 30;
      curlCmd += ' --max-time ' + timeout;
      curlCmd += ' -D ' + headerFile;
      curlCmd += " -o " + tmpFile + " '" + finalUrl.replace(/'/g, "'\\''") + "' 2>&1";
      
      var exitCode = os.system(curlCmd);
      
      var body = '';
      try { body = os.file.readFile(tmpFile); } catch(e) {}
      
      var headersRaw = '';
      try { headersRaw = os.file.readFile(headerFile); } catch(e) {}
      
      var status = 0;
      var statusMatch = headersRaw.match(/HTTP\\/[0-9.]+ (\\d+)/);
      if (statusMatch) status = parseInt(statusMatch[1], 10);
      
      // Cleanup temp files including body file
      var cleanupFiles = tmpFile + ' ' + headerFile;
      if (bodyFile) cleanupFiles += ' ' + bodyFile;
      try { os.system('rm -f ' + cleanupFiles + ' 2>/dev/null'); } catch(e) {}
      
      return { exitCode: exitCode, status: status, body: body, headers: headersRaw };
    }
    
    // Log token usage
    __logTokenUsage(tokenName, hostname, opts.method || 'GET', urlPath);
    
    try {
      // First attempt
      var result = __executeTokenRequest(injection);
      
      // Check for 401 Unauthorized - might need token refresh
      if (result.status === 401 && __tokenRefreshConfigs[tokenName]) {
        print('[TOKEN] Got 401, attempting OAuth token refresh for: ' + tokenName);
        
        var refreshResult = __refreshOAuthToken(tokenName);
        
        if (refreshResult.success) {
          // Retry with refreshed token
          injection = __tokenInjections[tokenName]; // Get updated injection
          __logTokenUsage(tokenName, hostname, opts.method || 'GET', urlPath + ' (retry after refresh)');
          result = __executeTokenRequest(injection);
        } else {
          print('[TOKEN] OAuth refresh failed: ' + refreshResult.error);
          // Continue with original 401 response
        }
      }
      
      if (result.exitCode !== 0 && !result.body) {
        return { err: 'Authenticated fetch failed with exit code ' + result.exitCode };
      }
      
      return { 
        ok: result.status >= 200 && result.status < 300,
        status: result.status || 200,
        body: result.body,
        headers: result.headers
      };
    } catch(e) {
      return { err: e.toString() };
    }
  }
  
  // System command execution (for child_process module)
  if (cmd === 'system.exec') {
    // a1 = command string
    if (!a1 || typeof a1 !== 'string') {
      return { err: 'Invalid command' };
    }
    
    // Extract command name for permission check
    var cmdParts = a1.trim().split(/\\s+/);
    var cmdName = cmdParts[0];
    // Handle path-based commands (e.g., /usr/bin/ls -> ls)
    if (cmdName.indexOf('/') >= 0) {
      cmdName = cmdName.split('/').pop();
    }
    
    if (!__checkPerm('system', cmdName) && !__checkPerm('system', '*')) {
      return { err: 'System command permission denied: ' + cmdName + '. Add it to \\'system\\' in ~/.pave/permissions.yaml to allow.' };
    }
    
    // Execute command and capture output
    var tmpFile = '/tmp/pave_exec_' + Date.now() + '_' + Math.random().toString(36).substr(2,6);
    var stdoutFile = tmpFile + '.stdout';
    var stderrFile = tmpFile + '.stderr';
    var exitFile = tmpFile + '.exit';
    
    // Build command that captures stdout, stderr, and exit code
    var execCmd = '(' + a1.replace(/'/g, "'\\''") + ') >' + stdoutFile + ' 2>' + stderrFile + '; echo $? >' + exitFile;
    
    try {
      os.system('/bin/sh -c \\'' + execCmd.replace(/'/g, "'\\''") + '\\'');
      
      var stdout = '';
      var stderr = '';
      var exitCode = 0;
      
      try { stdout = os.file.readFile(stdoutFile); } catch(e) {}
      try { stderr = os.file.readFile(stderrFile); } catch(e) {}
      try { 
        var exitStr = os.file.readFile(exitFile).trim();
        exitCode = parseInt(exitStr, 10) || 0;
      } catch(e) {}
      
      // Cleanup
      try { os.system('rm -f ' + stdoutFile + ' ' + stderrFile + ' ' + exitFile + ' 2>/dev/null'); } catch(e) {}
      
      return { 
        stdout: stdout,
        stderr: stderr,
        exitCode: exitCode,
        ok: exitCode === 0
      };
    } catch(e) {
      try { os.system('rm -f ' + stdoutFile + ' ' + stderrFile + ' ' + exitFile + ' 2>/dev/null'); } catch(ex) {}
      return { err: e.toString() };
    }
  }
  
  return { err: 'Unknown: ' + cmd };
};

// ============================================================
// PHASE 4: Load Sandbox APIs
// ============================================================
var __apisCode = os.file.readFile("${paths.sandboxApis.replace(/\\/g, '\\\\')}");
sandbox.eval(__apisCode);

// ============================================================
// PHASE 5: Execute User Script
// ============================================================
if (__logLevel >= 2) print('[SANDBOX] Starting: ${scriptName}');
if (__logLevel >= 2) print('');

var __userCode = os.file.readFile("${scriptPath.replace(/\\/g, '\\\\')}");
var __exitCode = 0;

try {
  evaluate(__userCode, { global: sandbox, fileName: "${scriptName}" });
} catch(e) {
  if (e && e.__sandboxExit) {
    __exitCode = e.code;
  } else {
    __exitCode = 1;
    print('');
    print('[SANDBOX ERROR] ' + e.toString());
    if (e.stack) print(e.stack);
  }
}

if (__logLevel >= 2) print('');
if (__logLevel >= 2) print('[SANDBOX] Complete (exit: ' + __exitCode + ')');

// Write result
try {
  var rj = JSON.stringify({ exit: __exitCode });
  var ra = new Uint8Array(rj.length);
  for (var ri = 0; ri < rj.length; ri++) ra[ri] = rj.charCodeAt(ri);
  os.file.writeTypedArrayToFile("${paths.result.replace(/\\/g, '\\\\')}", ra);
} catch(e) {}
`;

  fs.writeFileSync(paths.wrapper, wrapper);
}

/**
 * Generate the sandbox APIs code (runs inside sandbox via sandbox.eval)
 */
function generateSandboxApis(scriptPath, scriptArgs, scriptDir, tokenNames, modulesPermission) {
  const argsJson = JSON.stringify(['node', scriptPath, ...scriptArgs]);
  const tokenNamesJson = JSON.stringify(tokenNames || []);
  const modulesJson = JSON.stringify(modulesPermission || ['*']);
  
  return `// Sandbox APIs - runs inside sandbox scope
// Only __ipc__ is available for external access

// Modules permission list from permissions.yaml
var __allowedModules = ${modulesJson};

// Helper to check if a module is allowed
function __isModuleAllowed(mod) {
  // If '*' is in the list, all modules are allowed
  if (__allowedModules.indexOf('*') >= 0) return true;
  // Check exact match
  return __allowedModules.indexOf(mod) >= 0;
}

// Console
var console = {
  log: function() {
    var parts = [];
    for (var i = 0; i < arguments.length; i++) {
      var a = arguments[i];
      if (a === null) parts.push('null');
      else if (a === undefined) parts.push('undefined');
      else if (typeof a === 'object') {
        try { parts.push(JSON.stringify(a)); } catch(e) { parts.push(String(a)); }
      } else parts.push(String(a));
    }
    __ipc__('print', parts.join(' '));
  },
  error: function() {
    var parts = [];
    for (var i = 0; i < arguments.length; i++) {
      var a = arguments[i];
      if (typeof a === 'object') {
        try { parts.push(JSON.stringify(a)); } catch(e) { parts.push(String(a)); }
      } else parts.push(String(a));
    }
    __ipc__('error', parts.join(' '));
  },
  warn: function() {
    var args = ['[WARN]'];
    for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
    console.log.apply(null, args);
  },
  info: function() { console.log.apply(null, arguments); },
  debug: function() {
    var args = ['[DEBUG]'];
    for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
    console.log.apply(null, args);
  }
};

// Process
var process = {
  argv: ${argsJson},
  env: {},
  cwd: function() { return "${scriptDir.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"; },
  exit: function(code) { throw { __sandboxExit: true, code: code || 0 }; },
  platform: 'linux',
  version: 'v16.0.0-sandbox'
};

// Try to make process.env work via proxy if available
if (typeof Proxy !== 'undefined') {
  process.env = new Proxy({}, {
    get: function(t, n) {
      if (typeof n !== 'string') return undefined;
      var r = __ipc__('env.get', n);
      return r.val || '';
    }
  });
}

// Module cache
var __cache = {};

// Require
function require(mod) {
  if (__cache[mod]) return __cache[mod];
  
  if (mod === 'fs') {
    __cache[mod] = {
      readFileSync: function(p) {
        var r = __ipc__('fs.read', p);
        if (r.err) { var e = new Error(r.err); e.code = 'ENOENT'; throw e; }
        return r.data;
      },
      writeFileSync: function(p, d) {
        var r = __ipc__('fs.write', p, String(d));
        if (r.err) throw new Error(r.err);
      },
      existsSync: function(p) {
        var r = __ipc__('fs.exists', p);
        return r.exists === true;
      },
      readdirSync: function(p) {
        var r = __ipc__('fs.readdir', p);
        if (r.err) throw new Error(r.err);
        return r.data;
      },
      statSync: function(p) {
        var r = __ipc__('fs.exists', p);
        if (!r.exists) { var e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; }
        return {
          isFile: function() { return true; },
          isDirectory: function() { return false; },
          size: 0,
          mtime: new Date()
        };
      },
      readFile: function(p, o, cb) {
        if (typeof o === 'function') { cb = o; o = {}; }
        try { cb(null, this.readFileSync(p)); } catch(e) { cb(e); }
      },
      writeFile: function(p, d, o, cb) {
        if (typeof o === 'function') { cb = o; o = {}; }
        try { this.writeFileSync(p, d); cb(null); } catch(e) { cb(e); }
      }
    };
    return __cache[mod];
  }
  
  if (mod === 'path') {
    __cache[mod] = {
      join: function() {
        var parts = [];
        for (var i = 0; i < arguments.length; i++) parts.push(arguments[i]);
        return parts.join('/').replace(/\\/\\/+/g, '/');
      },
      resolve: function() {
        var parts = [];
        for (var i = 0; i < arguments.length; i++) parts.push(arguments[i]);
        var p = parts.join('/').replace(/\\/\\/+/g, '/');
        return p.charAt(0) === '/' ? p : '/' + p;
      },
      basename: function(p, ext) {
        var b = p.split('/').pop() || '';
        if (ext && b.slice(-ext.length) === ext) b = b.slice(0, -ext.length);
        return b;
      },
      dirname: function(p) {
        var parts = p.split('/');
        parts.pop();
        return parts.join('/') || '/';
      },
      extname: function(p) {
        var b = p.split('/').pop() || '';
        var i = b.lastIndexOf('.');
        return i > 0 ? b.slice(i) : '';
      },
      isAbsolute: function(p) { return p.charAt(0) === '/'; },
      sep: '/',
      delimiter: ':'
    };
    return __cache[mod];
  }
  
  if (mod === 'util') {
    __cache[mod] = {
      format: function() {
        var parts = [];
        for (var i = 0; i < arguments.length; i++) parts.push(arguments[i]);
        return parts.join(' ');
      },
      inspect: function(o) {
        try { return JSON.stringify(o, null, 2); } catch(e) { return String(o); }
      }
    };
    return __cache[mod];
  }
  
  if (mod === 'os') {
    __cache[mod] = {
      platform: function() { return 'linux'; },
      type: function() { return 'Linux'; },
      homedir: function() { return '/home/sandbox'; },
      tmpdir: function() { return '/tmp'; },
      hostname: function() { return 'sandbox'; },
      EOL: '\\n'
    };
    return __cache[mod];
  }
  
  if (mod === 'events') {
    function EventEmitter() { this._e = {}; }
    EventEmitter.prototype.on = function(n, f) {
      if (!this._e[n]) this._e[n] = [];
      this._e[n].push(f);
      return this;
    };
    EventEmitter.prototype.emit = function(n) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      var fns = this._e[n] || [];
      for (var j = 0; j < fns.length; j++) fns[j].apply(this, args);
      return fns.length > 0;
    };
    EventEmitter.prototype.removeListener = function(n, f) {
      var fns = this._e[n] || [];
      var idx = -1;
      for (var i = 0; i < fns.length; i++) { if (fns[i] === f) { idx = i; break; } }
      if (idx >= 0) fns.splice(idx, 1);
      return this;
    };
    __cache[mod] = { EventEmitter: EventEmitter };
    return __cache[mod];
  }
  
  // child_process module - requires explicit permission in permissions.yaml
  if (mod === 'child_process') {
    if (!__isModuleAllowed('child_process')) {
      throw new Error("Module 'child_process' is blocked in sandbox. Add 'child_process' to 'modules' in ~/.pave/permissions.yaml to allow.");
    }
    __cache[mod] = {
      execSync: function(cmd, opts) {
        opts = opts || {};
        var r = __ipc__('system.exec', cmd);
        if (r.err) {
          var e = new Error(r.err);
          e.status = 1;
          throw e;
        }
        if (r.exitCode !== 0) {
          var e = new Error('Command failed: ' + cmd + '\\n' + (r.stderr || ''));
          e.status = r.exitCode;
          e.stdout = r.stdout;
          e.stderr = r.stderr;
          throw e;
        }
        if (opts.encoding === 'utf8' || opts.encoding === 'utf-8') {
          return r.stdout;
        }
        return r.stdout;
      },
      exec: function(cmd, opts, cb) {
        if (typeof opts === 'function') { cb = opts; opts = {}; }
        opts = opts || {};
        try {
          var stdout = this.execSync(cmd, opts);
          if (cb) cb(null, stdout, '');
        } catch(e) {
          if (cb) cb(e, e.stdout || '', e.stderr || '');
        }
      },
      spawnSync: function(cmd, args, opts) {
        args = args || [];
        opts = opts || {};
        var fullCmd = cmd + ' ' + args.map(function(a) {
          return "'" + a.replace(/'/g, "'\\''") + "'";
        }).join(' ');
        var r = __ipc__('system.exec', fullCmd);
        if (r.err) {
          return { status: 1, error: new Error(r.err), stdout: '', stderr: r.err };
        }
        return {
          status: r.exitCode,
          stdout: r.stdout,
          stderr: r.stderr,
          error: r.exitCode !== 0 ? new Error('Command failed') : null
        };
      }
    };
    return __cache[mod];
  }
  
  // Check module permission from permissions.yaml
  // Modules like cluster, worker_threads, vm are blocked by default
  // unless explicitly allowed in permissions.yaml under 'modules'
  if (!__isModuleAllowed(mod)) {
    throw new Error("Module '" + mod + "' is blocked in sandbox. Add it to 'modules' in ~/.pave/permissions.yaml to allow.");
  }
  
  // Network - not implemented (even if allowed, sandbox doesn't have implementation)
  if (mod === 'http' || mod === 'https' || mod === 'net' || mod === 'dns') {
    throw new Error("Network module '" + mod + "' not available in sandbox. Use fetch() instead.");
  }
  
  throw new Error("Module '" + mod + "' not found.");
}

// CommonJS globals
var module = { exports: {} };
var exports = module.exports;
var __dirname = "${scriptDir.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}";
var __filename = "${scriptPath.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}";
var global = { console: console, process: process };

// Set require.main to module so "require.main === module" works for entry scripts
require.main = module;

// Global fetch function (uses curl via IPC)
function fetch(url, options) {
  options = options || {};
  
  var opts = {
    method: options.method || 'GET',
    headers: options.headers || {},
    body: options.body || null,
    timeout: options.timeout || 30000
  };
  
  var result = __ipc__('fetch', url, JSON.stringify(opts));
  
  if (result.err) {
    throw new Error(result.err);
  }
  
  // Return a Response-like object
  return {
    ok: result.ok,
    status: result.status,
    statusText: result.status >= 200 && result.status < 300 ? 'OK' : 'Error',
    headers: {
      get: function(name) {
        var match = result.headers.match(new RegExp('^' + name + ':\\\\s*(.*)$', 'im'));
        return match ? match[1].trim() : null;
      }
    },
    text: function() { return result.body; },
    json: function() { return JSON.parse(result.body); }
  };
}

// Also add to global
global.fetch = fetch;

// ============================================================
// SECURE TOKEN API
// ============================================================
// These functions allow sandboxed code to make authenticated requests
// without ever seeing the actual token values.

/**
 * List available token names
 * @returns {string[]} Array of token names that can be used with authenticatedFetch
 */
function listTokens() {
  var result = __ipc__('token.list');
  return result.tokens || [];
}

/**
 * Check if a token is available
 * @param {string} tokenName - Name of the token to check
 * @returns {boolean} True if token exists and has a value
 */
function hasToken(tokenName) {
  var result = __ipc__('token.has', tokenName);
  return result.has === true;
}

/**
 * Make an authenticated fetch request using a named token
 * The token is injected by the sandbox wrapper - never visible to this code
 * 
 * @param {string} tokenName - Name of the token to use (e.g., 'openai', 'github')
 * @param {string} url - URL to fetch (must be in token's allowed domains)
 * @param {object} [options] - Fetch options
 * @param {string} [options.method='GET'] - HTTP method
 * @param {object} [options.headers={}] - Additional headers (token header added automatically)
 * @param {string} [options.body] - Request body
 * @param {number} [options.timeout=30000] - Timeout in milliseconds
 * @returns {object} Response-like object with ok, status, text(), json()
 * @throws {Error} If token not found, domain not allowed, or request fails
 */
function authenticatedFetch(tokenName, url, options) {
  if (!tokenName || typeof tokenName !== 'string') {
    throw new Error('authenticatedFetch: tokenName is required');
  }
  if (!url || typeof url !== 'string') {
    throw new Error('authenticatedFetch: url is required');
  }
  
  options = options || {};
  
  var reqData = {
    url: url,
    method: options.method || 'GET',
    headers: options.headers || {},
    body: options.body || null,
    timeout: options.timeout || 30000
  };
  
  var result = __ipc__('token.fetch', tokenName, JSON.stringify(reqData));
  
  if (result.err) {
    throw new Error(result.err);
  }
  
  // Return a Response-like object
  return {
    ok: result.ok,
    status: result.status,
    statusText: result.status >= 200 && result.status < 300 ? 'OK' : 'Error',
    headers: {
      get: function(name) {
        var match = result.headers.match(new RegExp('^' + name + ':\\\\s*(.*)$', 'im'));
        return match ? match[1].trim() : null;
      }
    },
    text: function() { return result.body; },
    json: function() { return JSON.parse(result.body); }
  };
}

// Add token APIs to global
global.listTokens = listTokens;
global.hasToken = hasToken;
global.authenticatedFetch = authenticatedFetch;
`;
}

function cleanupWrapper(wrapperPath, sessionId) {
  try {
    if (sessionId) {
      const paths = getSessionPaths(sessionId);
      for (const key of Object.keys(paths)) {
        if (fs.existsSync(paths[key])) fs.unlinkSync(paths[key]);
      }
    } else if (wrapperPath && fs.existsSync(wrapperPath)) {
      fs.unlinkSync(wrapperPath);
    }
  } catch (e) {
    _logError(`[SANDBOX] Cleanup error: ${e.message}`);
  }
}

function readResult(sessionId) {
  const paths = getSessionPaths(sessionId);
  try {
    if (fs.existsSync(paths.result)) {
      return JSON.parse(fs.readFileSync(paths.result, 'utf8'));
    }
  } catch (e) {}
  return null;
}

module.exports = {
  transformToSandbox,
  analyzeScript,
  cleanupWrapper,
  readResult,
  getSessionPaths,
  SANDBOX_DIR
};
