/**
 * Permission Management Tool for PAVE Sandbox
 * Provides a clean API for managing sandbox permissions
 * 
 * SECURITY: Grant/Revoke/Clear actions require user confirmation
 * Only List and Check are immediate (read-only operations)
 * 
 * PERSISTENCE: 
 * - Permissions saved to: ~/.pave/permissions.yaml
 * - Tokens saved to: ~/.pave/tokens.yaml
 * 
 * BACKWARDS COMPATIBILITY:
 * - Reads legacy ~/.config/opencode-lite/permissions.json (with migration warning)
 * - Reads legacy ~/.env files (with migration warning)
 * - Auto-migrates to new YAML format when possible
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { parseYaml, stringifyYaml, addYamlHeader } = require('./utils/yaml');

// ============================================================
// FILE PATHS - New YAML-based configuration in ~/.pave/
// ============================================================

// New YAML file locations (primary)
const PAVE_DIR = path.join(os.homedir(), '.pave');
const TOKENS_FILE = path.join(PAVE_DIR, 'tokens.yaml');
const PERMISSION_FILE = path.join(PAVE_DIR, 'permissions.yaml');

// Legacy file locations (for backwards compatibility with deprecation warnings)
const LEGACY_PERMISSION_DIR = path.join(os.homedir(), '.config', 'opencode-lite');
const LEGACY_PERMISSION_FILE = path.join(LEGACY_PERMISSION_DIR, 'permissions.json');

// Legacy .env file locations for token values (deprecated)
const LEGACY_ENV_FILE_PATHS = [
  path.join(process.cwd(), '.env'),
  path.join(process.cwd(), 'src', 'packages', 'cnr-agent', '.env'),
  path.join(os.homedir(), '.env'),
  '/Users/raymond/pave-apps/openpave/src/packages/cnr-agent/.env'
];

// Track if deprecation warnings have been shown (only show once per session)
let _shownDeprecationWarning = {
  env: false,
  permissions: false
};

// ============================================================
// LOGGING VERBOSITY CONTROL
// ============================================================
// Controls which log messages are shown to avoid leaking info to LLM context
// Levels: 0 = silent, 1 = errors/warnings only, 2 = normal, 3 = verbose/debug
let _logLevel = 0; // Default: silent to prevent context leakage

/**
 * Set the logging verbosity level
 * @param {number} level - 0=silent, 1=errors/warnings, 2=normal, 3=verbose
 */
function setLogLevel(level) {
  _logLevel = typeof level === 'number' ? level : 0;
}

/**
 * Get current log level
 */
function getLogLevel() {
  return _logLevel;
}

// Internal logging helpers
function _logError(...args) {
  if (_logLevel >= 1) console.error(...args);
}

function _logWarn(...args) {
  if (_logLevel >= 1) console.warn(...args);
}

function _logInfo(...args) {
  if (_logLevel >= 2) console.log(...args);
}

function _logDebug(...args) {
  if (_logLevel >= 3) console.log(...args);
}

// Default safe system commands
// These provide baseline functionality for filesystem and text processing
// Users can customize by creating ~/.pave/permissions.yaml (see permissions.yaml.example)
const DEFAULT_SYSTEM_COMMANDS = [
  // Filesystem navigation and inspection
  'ls', 'dir', 'pwd', 'cat', 'head', 'tail', 'find', 'file', 'stat', 'du', 'df',
  // Text processing
  'grep', 'awk', 'sed', 'sort', 'uniq', 'wc', 'echo',
  // File operations
  'mkdir', 'rmdir', 'rm', 'cp', 'mv', 'chmod', 'chown', 'touch',
  // Command discovery
  'which', 'whereis', 'type'
];

// In-memory permission storage
// SECURITY: Network and filesystem default to empty (deny by default)
// System commands have sensible defaults for common operations
// Users can customize via ~/.pave/permissions.yaml
const permissions = {
  network: new Set(),      // Allowed domains
  filesystem: {
    read: new Set(),       // SECURITY: No read access by default - must be explicitly granted
    write: new Set()       // Allowed write paths
  },
  modules: new Set(['*']), // Unrestricted require/import by default
  system: new Set(DEFAULT_SYSTEM_COMMANDS),  // Default safe commands
  skills: {
    allowed: new Set(),    // Allowed skill patterns (e.g., "gmail.*", "calendar.read")
    denied: new Set()      // Denied skill patterns - takes precedence over allowed
  }
};

// Token configurations storage
// Structure: { tokenName: { env, type, domains, placement, refreshEnv?, refreshUrl?, ... } }
const tokenConfigs = new Map();

// PRIVATE token values storage - NEVER leaked to child processes
// This stores actual token values loaded from .env files
// Keys are env var names (e.g., 'GMAIL_CLIENT_ID'), values are the token strings
const _privateTokenValues = new Map();

// Token audit log (in-memory, recent entries only)
const tokenAuditLog = [];
const MAX_AUDIT_ENTRIES = 1000;

// Track permission file modification time to avoid redundant reloads
let _lastPermissionFileMtime = 0;
let _lastEnvFileMtime = 0;
let _lastEnvFilePath = null;

// Store for pending permission requests awaiting user confirmation
const pendingPermissionRequests = new Map();

// Load saved permissions on module initialization
// This is deferred to allow savePermissions to be defined first
let _permissionsLoaded = false;
function _ensurePermissionsLoaded() {
  if (!_permissionsLoaded) {
    _permissionsLoaded = true;
    loadPermissions();
  }
}

// Generate unique request ID
function generateRequestId() {
  return `perm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Normalize hostname for comparison
 */
function normalizeHostname(hostname) {
  return hostname.toLowerCase().replace(/^www\./, '');
}

/**
 * Check if hostname matches a domain pattern
 * Supports:
 *   - Exact match: "api.example.com"
 *   - Subdomain wildcard: "*.example.com" matches "api.example.com", "foo.bar.example.com"
 *   - Full wildcard: "*" matches everything
 * 
 * @param {string} hostname - The hostname to check (e.g., "us4.api.mailchimp.com")
 * @param {string} pattern - The pattern to match against (e.g., "*.api.mailchimp.com")
 * @returns {boolean} - True if hostname matches the pattern
 */
function domainMatches(hostname, pattern) {
  // Full wildcard matches everything
  if (pattern === '*') return true;
  
  // Normalize both for comparison
  const normalizedHost = normalizeHostname(hostname);
  const normalizedPattern = normalizeHostname(pattern);
  
  // Exact match
  if (normalizedHost === normalizedPattern) return true;
  
  // Wildcard pattern: *.example.com
  if (normalizedPattern.startsWith('*.')) {
    const suffix = normalizedPattern.slice(1); // ".example.com"
    // Host must end with the suffix (e.g., "api.example.com" ends with ".example.com")
    return normalizedHost.endsWith(suffix);
  }
  
  // Subdomain match: pattern "example.com" matches "api.example.com"
  if (normalizedHost.endsWith('.' + normalizedPattern)) return true;
  
  return false;
}

/**
 * Normalize a filesystem path to prevent traversal attacks
 * Resolves '..' and '.' segments, handles symlinks via realpath when possible
 * 
 * IMPORTANT: When the target file doesn't exist (e.g., for write operations),
 * we still need to resolve symlinks in the parent directory chain. This is
 * critical on macOS where /tmp -> /private/tmp. Without this, permission
 * checks fail when the pattern is "/tmp/*" but the path resolves to
 * "/private/tmp/file" (or vice versa depending on which exists).
 * 
 * @param {string} inputPath - The path to normalize
 * @returns {string} - Normalized absolute path with symlinks resolved
 */
function normalizePath(inputPath) {
  if (!inputPath || typeof inputPath !== 'string') {
    return inputPath;
  }
  
  // Use path.resolve to normalize '..' and '.' segments
  // This converts relative paths to absolute and resolves traversal
  let normalized = path.resolve(inputPath);
  
  // Try to resolve symlinks for the full path first
  try {
    normalized = fs.realpathSync(normalized);
    return normalized;
  } catch (e) {
    // File may not exist yet (e.g., for write operations)
    // Try to resolve symlinks for the parent directory instead
    // This handles cases like /tmp/newfile.txt where /tmp is a symlink
    // but newfile.txt doesn't exist yet
  }
  
  // Walk up the directory tree to find the deepest existing path
  // and resolve symlinks from there
  let current = normalized;
  const missingParts = [];
  
  while (current && current !== '/') {
    try {
      const realCurrent = fs.realpathSync(current);
      // Found an existing path - combine it with the missing parts
      if (missingParts.length > 0) {
        return path.join(realCurrent, ...missingParts.reverse());
      }
      return realCurrent;
    } catch (e) {
      // This part doesn't exist, save it and try the parent
      missingParts.push(path.basename(current));
      current = path.dirname(current);
    }
  }
  
  // Nothing in the path exists (unusual), return the original normalized path
  // Prepend root if we have missing parts
  if (missingParts.length > 0) {
    return '/' + missingParts.reverse().join(path.sep);
  }
  return normalized;
}

/**
 * Check if path matches a pattern
 * SECURITY: Normalizes both path and pattern to prevent traversal attacks
 */
function pathMatches(inputPath, pattern) {
  if (pattern === '*') return true;
  
  // Normalize the input path to prevent traversal attacks like '../../../etc/passwd'
  const normalizedPath = normalizePath(inputPath);
  
  if (pattern.endsWith('/*')) {
    // Normalize the pattern base path as well
    const patternBase = normalizePath(pattern.slice(0, -2));
    // Ensure the normalized path starts with the pattern base
    // Add path separator check to prevent '/tmp/evil' matching '/tmp' pattern
    return normalizedPath === patternBase || normalizedPath.startsWith(patternBase + path.sep);
  }
  
  // For exact matches, compare normalized paths
  const normalizedPattern = normalizePath(pattern);
  return normalizedPath === normalizedPattern;
}

// ============================================================
// TOKEN MANAGEMENT
// ============================================================

/**
 * Register a token configuration
 * @param {string} name - Token identifier (e.g., 'openai', 'github')
 * @param {object} config - Token configuration
 * @param {string} config.env - Environment variable name for token
 * @param {string} config.type - 'api_key' or 'oauth'
 * @param {string[]} config.domains - Allowed domains for this token
 * @param {object} config.placement - Where to inject token
 * @param {string} config.placement.type - 'header', 'query', or 'body'
 * @param {string} config.placement.name - Header/param name
 * @param {string} [config.placement.format] - Format string with {token} placeholder
 * @param {string} [config.refreshEnv] - Environment variable for refresh token (OAuth)
 * @param {string} [config.refreshUrl] - URL for token refresh (OAuth)
 * @param {string} [config.clientIdEnv] - Environment variable for client ID (OAuth)
 * @param {string} [config.clientSecretEnv] - Environment variable for client secret (OAuth)
 */
function registerToken(name, config) {
  // Validate required fields
  if (!name || typeof name !== 'string') {
    throw new Error('Token name is required');
  }
  if (!config.env || typeof config.env !== 'string') {
    throw new Error(`Token '${name}': 'env' is required`);
  }
  if (!config.type || !['api_key', 'oauth'].includes(config.type)) {
    throw new Error(`Token '${name}': 'type' must be 'api_key' or 'oauth'`);
  }
  if (!Array.isArray(config.domains) || config.domains.length === 0) {
    throw new Error(`Token '${name}': 'domains' must be a non-empty array`);
  }
  if (!config.placement || !config.placement.type) {
    throw new Error(`Token '${name}': 'placement.type' is required`);
  }
  if (!['header', 'query', 'body'].includes(config.placement.type)) {
    throw new Error(`Token '${name}': 'placement.type' must be 'header', 'query', or 'body'`);
  }
  if (config.placement.type !== 'body' && !config.placement.name) {
    throw new Error(`Token '${name}': 'placement.name' is required for header/query placement`);
  }
  
  // OAuth-specific validation
  if (config.type === 'oauth') {
    if (!config.refreshEnv) {
      _logWarn(`[TOKEN] Warning: OAuth token '${name}' has no refreshEnv - refresh will not work`);
    }
    if (!config.refreshUrl) {
      _logWarn(`[TOKEN] Warning: OAuth token '${name}' has no refreshUrl - refresh will not work`);
    }
  }
  
  // Normalize domains
  const normalizedConfig = {
    ...config,
    domains: config.domains.map(d => normalizeHostname(d))
  };
  
  tokenConfigs.set(name, normalizedConfig);
  _logDebug(`[TOKEN] Registered token '${name}' for domains: ${normalizedConfig.domains.join(', ')}`);
  
  return true;
}

/**
 * Unregister a token
 */
function unregisterToken(name) {
  if (tokenConfigs.has(name)) {
    tokenConfigs.delete(name);
    _logDebug(`[TOKEN] Unregistered token '${name}'`);
    return true;
  }
  return false;
}

/**
 * Check if a token exists and has valid credentials available
 * For API keys: checks if the token env var is set
 * For OAuth: checks if refresh token is available (can obtain access token)
 */
function hasToken(name) {
  const config = tokenConfigs.get(name);
  if (!config) return false;
  
  // For OAuth tokens, we can refresh even without an access token
  if (config.type === 'oauth') {
    const refreshToken = _privateTokenValues.get(config.refreshEnv) || process.env[config.refreshEnv];
    const clientId = _privateTokenValues.get(config.clientIdEnv) || process.env[config.clientIdEnv];
    const clientSecret = _privateTokenValues.get(config.clientSecretEnv) || process.env[config.clientSecretEnv];
    // Has credentials if we can refresh
    return !!(refreshToken && clientId && clientSecret);
  }
  
  // For API keys, check the token value directly
  const value = _privateTokenValues.get(config.env) || process.env[config.env];
  return !!(value && value.length > 0);
}

/**
 * List all registered token names
 */
function listTokens() {
  return Array.from(tokenConfigs.keys());
}

/**
 * Get token configuration (without the actual token value)
 */
function getTokenConfig(name) {
  const config = tokenConfigs.get(name);
  if (!config) return null;
  
  // Return config without exposing env var names that could leak info
  return {
    name,
    type: config.type,
    domains: [...config.domains],
    placement: { ...config.placement },
    hasRefresh: config.type === 'oauth' && !!config.refreshEnv && !!config.refreshUrl
  };
}

/**
 * Check if a domain is allowed for a given token
 */
function isTokenDomainAllowed(tokenName, hostname) {
  const config = tokenConfigs.get(tokenName);
  if (!config) return false;
  
  for (const allowed of config.domains) {
    if (domainMatches(hostname, allowed)) return true;
  }
  
  return false;
}

/**
 * Log token usage for audit purposes
 */
function logTokenUsage(tokenName, domain, sessionId, method, path) {
  const entry = {
    timestamp: new Date().toISOString(),
    token: tokenName,
    domain,
    sessionId: sessionId || 'unknown',
    method: method || 'GET',
    path: path || '/'
  };
  
  tokenAuditLog.push(entry);
  
  // Keep only recent entries
  while (tokenAuditLog.length > MAX_AUDIT_ENTRIES) {
    tokenAuditLog.shift();
  }
  
  _logInfo(`[TOKEN AUDIT] ${entry.timestamp} | ${tokenName} | ${domain} | ${method} ${path} | session:${sessionId}`);
}

/**
 * Get recent token audit log entries
 */
function getTokenAuditLog(limit = 100) {
  return tokenAuditLog.slice(-limit);
}

/**
 * Get a secure env var value - checks private map first, then process.env
 * This ensures tokens loaded from .env are accessible without leaking to child processes
 * INTERNAL USE ONLY
 */
function _getSecureEnvValue(envVarName) {
  // First check private map (loaded from .env files securely)
  if (_privateTokenValues.has(envVarName)) {
    return _privateTokenValues.get(envVarName);
  }
  // Fall back to process.env (for vars exported in shell)
  return process.env[envVarName] || null;
}

/**
 * Set a secure env var value (e.g., after OAuth refresh)
 * Stores in private map, NOT in process.env
 * INTERNAL USE ONLY
 */
function _setSecureEnvValue(envVarName, value) {
  _privateTokenValues.set(envVarName, value);
}

/**
 * Get the actual token value (INTERNAL USE ONLY - never expose to sandbox)
 * This function should only be called from trusted IPC bridge code
 */
function _getTokenValue(name) {
  const config = tokenConfigs.get(name);
  if (!config) return null;
  
  return _getSecureEnvValue(config.env);
}

/**
 * Get the refresh token value (INTERNAL USE ONLY)
 */
function _getRefreshTokenValue(name) {
  const config = tokenConfigs.get(name);
  if (!config || config.type !== 'oauth' || !config.refreshEnv) return null;
  
  return _getSecureEnvValue(config.refreshEnv);
}

/**
 * Get OAuth client credentials (INTERNAL USE ONLY)
 */
function _getOAuthClientCredentials(name) {
  const config = tokenConfigs.get(name);
  if (!config || config.type !== 'oauth') return null;
  
  return {
    clientId: config.clientIdEnv ? _getSecureEnvValue(config.clientIdEnv) : null,
    clientSecret: config.clientSecretEnv ? _getSecureEnvValue(config.clientSecretEnv) : null,
    refreshUrl: config.refreshUrl
  };
}

/**
 * Encode a string to Base64
 * @param {string} str - String to encode
 * @returns {string} Base64 encoded string
 */
function base64Encode(str) {
  return Buffer.from(str, 'utf8').toString('base64');
}

/**
 * Decode a Base64 string
 * @param {string} str - Base64 string to decode
 * @returns {string} Decoded string
 */
function base64Decode(str) {
  return Buffer.from(str, 'base64').toString('utf8');
}

/**
 * Apply encoding to a token value
 * 
 * Supported encodings:
 *   - 'none' or undefined: No encoding (default)
 *   - 'base64': Base64 encode the token
 *   - 'basic': Base64 encode as "token:" (token as username, empty password)
 *   - 'basic_with_x': Base64 encode as "token:x" (token as username, 'x' as password)
 *   - 'basic_with_password': Base64 encode as "token:password" (requires passwordEnv in config)
 *   - 'url': URL encode the token
 * 
 * @param {string} tokenValue - The raw token value
 * @param {object} config - Token configuration
 * @returns {string} Encoded token value
 */
function applyTokenEncoding(tokenValue, config) {
  const encoding = config.encoding || config.placement?.encoding || 'none';
  
  switch (encoding.toLowerCase()) {
    case 'none':
      return tokenValue;
    
    case 'base64':
      return base64Encode(tokenValue);
    
    case 'basic':
      // Basic auth with token as username, empty password
      return base64Encode(`${tokenValue}:`);
    
    case 'basic_with_x':
      // Basic auth with token as username, 'x' as password (BambooHR style)
      return base64Encode(`${tokenValue}:x`);
    
    case 'basic_with_password':
      // Basic auth with token as username, password from config
      const password = config.passwordEnv ? _getSecureEnvValue(config.passwordEnv) : '';
      return base64Encode(`${tokenValue}:${password || ''}`);
    
    case 'basic_reverse':
      // Basic auth with username from config, token as password
      const username = config.usernameEnv ? _getSecureEnvValue(config.usernameEnv) : '';
      return base64Encode(`${username || ''}:${tokenValue}`);
    
    case 'url':
      return encodeURIComponent(tokenValue);
    
    default:
      _logWarn(`[TOKEN] Unknown encoding '${encoding}', using raw value`);
      return tokenValue;
  }
}

/**
 * Build injection data for a token (INTERNAL USE ONLY)
 * Returns the data needed to inject the token into a request
 */
function _buildTokenInjection(name) {
  const config = tokenConfigs.get(name);
  if (!config) return null;
  
  const tokenValue = _getTokenValue(name);
  if (!tokenValue) return null;
  
  const placement = config.placement;
  
  // Apply encoding first (before format)
  let encodedValue = applyTokenEncoding(tokenValue, config);
  
  // Then apply format if specified
  let formattedValue = encodedValue;
  if (placement.format) {
    formattedValue = placement.format.replace('{token}', encodedValue);
  }
  
  return {
    type: placement.type,
    name: placement.name,
    value: formattedValue,
    domains: config.domains
  };
}

/**
 * Refresh an OAuth token (INTERNAL USE ONLY)
 * This is called when a 401 is received and the token might be expired
 * 
 * @param {string} name - Token name
 * @returns {object} Result with success/error and new token info
 */
function _refreshOAuthToken(name) {
  const config = tokenConfigs.get(name);
  if (!config) {
    return { success: false, error: 'Token not found' };
  }
  
  if (config.type !== 'oauth') {
    return { success: false, error: 'Token is not OAuth type' };
  }
  
  const refreshToken = _getRefreshTokenValue(name);
  if (!refreshToken) {
    return { success: false, error: 'No refresh token available' };
  }
  
  const creds = _getOAuthClientCredentials(name);
  if (!creds.refreshUrl) {
    return { success: false, error: 'No refresh URL configured' };
  }
  
  // Build refresh request body
  const bodyParams = new URLSearchParams();
  bodyParams.append('grant_type', 'refresh_token');
  bodyParams.append('refresh_token', refreshToken);
  
  if (creds.clientId) {
    bodyParams.append('client_id', creds.clientId);
  }
  if (creds.clientSecret) {
    bodyParams.append('client_secret', creds.clientSecret);
  }
  
  // Use child_process to make the request synchronously
  // This is a bit hacky but necessary for the sandbox which is synchronous
  const { execSync } = require('child_process');
  
  try {
    const curlCmd = `curl -s -S -X POST -H "Content-Type: application/x-www-form-urlencoded" -d '${bodyParams.toString()}' '${creds.refreshUrl}'`;
    const result = execSync(curlCmd, { encoding: 'utf8', timeout: 30000 });
    
    const response = JSON.parse(result);
    
    if (response.access_token) {
      // Update secure storage with new token (NOT process.env to prevent leakage)
      _setSecureEnvValue(config.env, response.access_token);
      
      // Update refresh token if a new one was provided
      if (response.refresh_token && config.refreshEnv) {
        _setSecureEnvValue(config.refreshEnv, response.refresh_token);
      }
      
      _logDebug(`[TOKEN] Successfully refreshed OAuth token '${name}'`);
      logTokenUsage(name, 'oauth-refresh', 'system', 'POST', creds.refreshUrl);
      
      return {
        success: true,
        accessToken: response.access_token,
        expiresIn: response.expires_in
      };
    } else if (response.error) {
      _logWarn(`[TOKEN] OAuth refresh failed for '${name}': ${response.error}`);
      return { success: false, error: response.error_description || response.error };
    } else {
      return { success: false, error: 'Unexpected response from refresh endpoint' };
    }
  } catch (err) {
    _logWarn(`[TOKEN] OAuth refresh error for '${name}': ${err.message}`);
    return { success: false, error: err.message };
  }
}

/**
 * Build OAuth refresh data for use in sandbox wrapper
 * Returns the data needed to perform OAuth refresh (without actual token values)
 */
function _buildOAuthRefreshConfig(name) {
  const config = tokenConfigs.get(name);
  if (!config || config.type !== 'oauth') return null;
  
  const creds = _getOAuthClientCredentials(name);
  const refreshToken = _getRefreshTokenValue(name);
  
  if (!creds.refreshUrl || !refreshToken) return null;
  
  return {
    refreshUrl: creds.refreshUrl,
    refreshToken: refreshToken,
    clientId: creds.clientId,
    clientSecret: creds.clientSecret,
    tokenEnv: config.env,
    refreshEnv: config.refreshEnv,
    domains: config.domains  // Include domains for injection creation after refresh
  };
}

/**
 * Grant a permission
 */
function grantPermission(type, target, reason = null) {
  _logDebug(`[PERMISSION] Granting ${type} for: ${target}`);
  
  switch (type.toLowerCase()) {
    case 'network':
      permissions.network.add(normalizeHostname(target));
      break;
    case 'fs.read':
    case 'filesystem.read':
      permissions.filesystem.read.add(target);
      break;
    case 'fs.write':
    case 'filesystem.write':
      permissions.filesystem.write.add(target);
      break;
    case 'module':
    case 'modules':
    case 'require':
      permissions.modules.add(target);
      break;
    case 'system':
    case 'command':
      permissions.system.add(target);
      break;
    default:
      _logWarn(`[PERMISSION] Unknown type: ${type}`);
      return false;
  }
  
  _logInfo(`[PERMISSION] Granted: ${type} -> ${target}`);
  savePermissions(); // Auto-save after grant
  return true;
}

/**
 * Revoke a permission
 */
function revokePermission(type, target) {
  _logDebug(`[PERMISSION] Revoking ${type} for: ${target}`);
  
  switch (type.toLowerCase()) {
    case 'network':
      permissions.network.delete(normalizeHostname(target));
      break;
    case 'fs.read':
    case 'filesystem.read':
      permissions.filesystem.read.delete(target);
      break;
    case 'fs.write':
    case 'filesystem.write':
      permissions.filesystem.write.delete(target);
      break;
    case 'module':
    case 'modules':
    case 'require':
      permissions.modules.delete(target);
      break;
    case 'system':
    case 'command':
      permissions.system.delete(target);
      break;
  }
  
  _logInfo(`[PERMISSION] Revoked: ${type} -> ${target}`);
  savePermissions(); // Auto-save after revoke
  return true;
}

/**
 * Check if a permission exists
 */
function checkPermission(type, target) {
  switch (type.toLowerCase()) {
    case 'network':
      for (const allowed of permissions.network) {
        if (domainMatches(target, allowed)) {
          return true;
        }
      }
      return false;
      
    case 'fs.read':
    case 'filesystem.read':
      for (const allowed of permissions.filesystem.read) {
        if (pathMatches(target, allowed)) return true;
      }
      return false;
      
    case 'fs.write':
    case 'filesystem.write':
      for (const allowed of permissions.filesystem.write) {
        if (pathMatches(target, allowed)) return true;
      }
      return false;
      
    case 'module':
    case 'modules':
    case 'require':
      if (permissions.modules.has('*')) return true;
      return permissions.modules.has(target);
      
    case 'system':
    case 'command':
      if (permissions.system.has('*')) return true;
      return permissions.system.has(target);
    
    case 'skill':
    case 'skills':
      return checkSkillPermission(target);
      
    default:
      return false;
  }
}

/**
 * Check if a skill tool is allowed
 * Supports patterns like "gmail.*", "calendar.read", or "*"
 * @param {string} skillTool - Full tool name (e.g., "gmail.profile")
 * @returns {boolean} - True if allowed
 */
function checkSkillPermission(skillTool) {
  // First check denied list (takes precedence)
  for (const denied of permissions.skills.denied) {
    if (skillPatternMatches(skillTool, denied)) {
      _logDebug(`[PERMISSION] Skill ${skillTool} denied by pattern: ${denied}`);
      return false;
    }
  }
  
  // Then check allowed list
  for (const allowed of permissions.skills.allowed) {
    if (skillPatternMatches(skillTool, allowed)) {
      _logDebug(`[PERMISSION] Skill ${skillTool} allowed by pattern: ${allowed}`);
      return true;
    }
  }
  
  // Not explicitly allowed
  _logDebug(`[PERMISSION] Skill ${skillTool} not in allowed list`);
  return false;
}

/**
 * Check if a skill tool matches a permission pattern
 * Patterns: "*" (all), "gmail_*" (all gmail commands), "gmail_profile" (exact)
 * @param {string} skillTool - Full tool name (e.g., "gmail_profile")
 * @param {string} pattern - Permission pattern
 * @returns {boolean}
 */
function skillPatternMatches(skillTool, pattern) {
  if (pattern === '*') return true;
  
  // Wildcard pattern: "gmail_*" or "gmail.*" (support both for compatibility)
  if (pattern.endsWith('_*') || pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -2); // "gmail"
    return skillTool.startsWith(prefix + '_');
  }
  
  // Exact match
  return skillTool === pattern;
}

/**
 * List all permissions
 */
function listPermissions() {
  return {
    network: Array.from(permissions.network),
    filesystem: {
      read: Array.from(permissions.filesystem.read),
      write: Array.from(permissions.filesystem.write)
    },
    modules: Array.from(permissions.modules),
    system: Array.from(permissions.system),
    skills: {
      allowed: Array.from(permissions.skills.allowed),
      denied: Array.from(permissions.skills.denied)
    }
  };
}

/**
 * Clear all permissions
 */
function clearPermissions() {
  permissions.network.clear();
  permissions.filesystem.read.clear();
  permissions.filesystem.write.clear();
  permissions.modules.clear();
  permissions.system.clear();
  permissions.skills.allowed.clear();
  permissions.skills.denied.clear();
  _logInfo(`[PERMISSION] All permissions cleared`);
  savePermissions(); // Auto-save after clear
  return true;
}

/**
 * Actions that require user confirmation (write operations)
 */
const CONFIRMATION_REQUIRED_ACTIONS = ['grant', 'revoke', 'clear'];

/**
 * Execute permission management actions
 * Write operations (grant/revoke/clear) return pending state requiring confirmation
 * Read operations (list/check) execute immediately
 */
function executePermission(args) {
  const { action, type, target, reason } = args;
  
  _logDebug(`[PERMISSION] Executing action: ${action}`);
  
  try {
    // Read-only operations execute immediately
    if (action === 'check') {
      if (!type || !target) {
        return {
          success: false,
          error: "Missing required parameters: 'type' and 'target' are required for check action"
        };
      }
      const allowed = checkPermission(type, target);
      return {
        success: true,
        action: 'check',
        type,
        target,
        allowed,
        message: allowed 
          ? `Permission ALLOWED: ${type} -> ${target}`
          : `Permission DENIED: ${type} -> ${target}`
      };
    }
    
    if (action === 'list') {
      const perms = listPermissions();
      return {
        success: true,
        action: 'list',
        permissions: perms,
        message: `Current permissions listed`
      };
    }
    
    // Write operations require user confirmation
    if (CONFIRMATION_REQUIRED_ACTIONS.includes(action)) {
      // Validate parameters for grant/revoke
      if ((action === 'grant' || action === 'revoke') && (!type || !target)) {
        return {
          success: false,
          error: `Missing required parameters: 'type' and 'target' are required for ${action} action`
        };
      }
      
      // Skip confirmation if permission already exists (for grant) or doesn't exist (for revoke)
      if (action === 'grant') {
        const alreadyAllowed = checkPermission(type, target);
        if (alreadyAllowed) {
          _logInfo(`[PERMISSION] Permission already exists, skipping confirmation: ${type} -> ${target}`);
          return {
            success: true,
            action: 'grant',
            type,
            target,
            reason,
            alreadyExists: true,
            message: `Permission already granted: ${type} -> ${target}`
          };
        }
      }
      
      if (action === 'revoke') {
        const currentlyAllowed = checkPermission(type, target);
        if (!currentlyAllowed) {
          _logInfo(`[PERMISSION] Permission doesn't exist, skipping confirmation: ${type} -> ${target}`);
          return {
            success: true,
            action: 'revoke',
            type,
            target,
            reason,
            alreadyRevoked: true,
            message: `Permission already revoked (not granted): ${type} -> ${target}`
          };
        }
      }
      
      // Create pending request
      const requestId = generateRequestId();
      const request = {
        id: requestId,
        action,
        type,
        target,
        reason: reason || 'No reason provided',
        timestamp: Date.now(),
        status: 'pending'
      };
      
      pendingPermissionRequests.set(requestId, request);
      
      // Build user-friendly description
      let description;
      switch (action) {
        case 'grant':
          description = `Grant ${type} permission for: ${target}`;
          break;
        case 'revoke':
          description = `Revoke ${type} permission for: ${target}`;
          break;
        case 'clear':
          description = `Clear ALL permissions (lock down sandbox)`;
          break;
      }
      
      _logDebug(`[PERMISSION] Created pending request: ${requestId}`);
      _logInfo(`[PERMISSION] Awaiting user confirmation for: ${description}`);
      
      return {
        success: true,
        pending: true,
        requiresConfirmation: true,
        requestId,
        action,
        type,
        target,
        reason: request.reason,
        description,
        message: `Permission change requested - awaiting user confirmation:\n${description}\nReason: ${request.reason}`
      };
    }
    
    return {
      success: false,
      error: `Unknown action: ${action}. Valid actions: grant, revoke, check, list, clear`
    };
    
  } catch (error) {
    _logError(`[PERMISSION] Error: ${error.message}`);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Confirm a pending permission request (called when user approves)
 */
function confirmPermissionRequest(requestId) {
  const request = pendingPermissionRequests.get(requestId);
  
  if (!request) {
    return {
      success: false,
      error: `Permission request not found: ${requestId}`
    };
  }
  
  if (request.status !== 'pending') {
    return {
      success: false,
      error: `Permission request already ${request.status}: ${requestId}`
    };
  }
  
  _logInfo(`[PERMISSION] User CONFIRMED request: ${requestId}`);
  
  try {
    let result;
    
    switch (request.action) {
      case 'grant':
        result = grantPermission(request.type, request.target, request.reason);
        request.status = 'approved';
        pendingPermissionRequests.set(requestId, request);
        return {
          success: true,
          action: 'grant',
          type: request.type,
          target: request.target,
          reason: request.reason,
          result,
          confirmed: true,
          message: `Permission GRANTED (user confirmed): ${request.type} -> ${request.target}`
        };
        
      case 'revoke':
        result = revokePermission(request.type, request.target);
        request.status = 'approved';
        pendingPermissionRequests.set(requestId, request);
        return {
          success: true,
          action: 'revoke',
          type: request.type,
          target: request.target,
          result,
          confirmed: true,
          message: `Permission REVOKED (user confirmed): ${request.type} -> ${request.target}`
        };
        
      case 'clear':
        result = clearPermissions();
        request.status = 'approved';
        pendingPermissionRequests.set(requestId, request);
        return {
          success: true,
          action: 'clear',
          result,
          confirmed: true,
          message: `All permissions CLEARED (user confirmed) - sandbox locked down`
        };
        
      default:
        return {
          success: false,
          error: `Unknown action in request: ${request.action}`
        };
    }
  } catch (error) {
    request.status = 'error';
    pendingPermissionRequests.set(requestId, request);
    return {
      success: false,
      error: `Failed to execute confirmed request: ${error.message}`
    };
  }
}

/**
 * Deny a pending permission request (called when user rejects)
 */
function denyPermissionRequest(requestId) {
  const request = pendingPermissionRequests.get(requestId);
  
  if (!request) {
    return {
      success: false,
      error: `Permission request not found: ${requestId}`
    };
  }
  
  if (request.status !== 'pending') {
    return {
      success: false,
      error: `Permission request already ${request.status}: ${requestId}`
    };
  }
  
  _logInfo(`[PERMISSION] User DENIED request: ${requestId}`);
  
  request.status = 'denied';
  pendingPermissionRequests.set(requestId, request);
  
  return {
    success: true,
    denied: true,
    requestId,
    action: request.action,
    type: request.type,
    target: request.target,
    message: `Permission request DENIED by user: ${request.action} ${request.type || ''} ${request.target || ''}`
  };
}

/**
 * Get a pending permission request by ID
 */
function getPendingRequest(requestId) {
  return pendingPermissionRequests.get(requestId) || null;
}

/**
 * Get all pending permission requests
 */
function getAllPendingRequests() {
  const pending = [];
  for (const [id, request] of pendingPermissionRequests) {
    if (request.status === 'pending') {
      pending.push(request);
    }
  }
  return pending;
}

/**
 * Clean up old pending requests (older than 5 minutes)
 */
function cleanupOldRequests() {
  const maxAge = 5 * 60 * 1000; // 5 minutes
  const now = Date.now();
  
  for (const [id, request] of pendingPermissionRequests) {
    if (now - request.timestamp > maxAge) {
      _logDebug(`[PERMISSION] Cleaning up expired request: ${id}`);
      pendingPermissionRequests.delete(id);
    }
  }
}

/**
 * Save permissions to disk
 * Saves to ~/.pave/permissions.yaml
 */
function savePermissions() {
  try {
    // Ensure directory exists
    if (!fs.existsSync(PAVE_DIR)) {
      fs.mkdirSync(PAVE_DIR, { recursive: true, mode: 0o700 });
    }
    
    // Convert token configs Map to object for serialization
    const tokensObj = {};
    for (const [name, config] of tokenConfigs) {
      tokensObj[name] = config;
    }
    
    // Convert Sets to arrays for serialization
    const data = {
      version: 4,  // Bumped version for YAML migration
      savedAt: new Date().toISOString(),
      permissions: {
        network: Array.from(permissions.network),
        filesystem: {
          read: Array.from(permissions.filesystem.read),
          write: Array.from(permissions.filesystem.write)
        },
        modules: Array.from(permissions.modules),
        system: Array.from(permissions.system),
        skills: {
          allowed: Array.from(permissions.skills.allowed),
          denied: Array.from(permissions.skills.denied)
        }
      },
      tokens: tokensObj
    };
    
    const header = `PAVE Permissions Configuration
Manages sandbox permissions and token configurations.
This file should have restricted permissions (chmod 600).

Permission Categories:
  - network: Allowed domains for HTTP requests
  - filesystem.read: Paths allowed for reading
  - filesystem.write: Paths allowed for writing
  - modules: Allowed Node.js modules (* = all)
  - system: Allowed system commands
  - skills.allowed: Allowed skill patterns (e.g., "gmail_*")
  - skills.denied: Denied skill patterns (takes precedence)

Token Configuration:
  - Each token has: env, type, domains, placement
  - OAuth tokens also have: refreshEnv, refreshUrl, clientIdEnv, clientSecretEnv`;
    
    const yamlContent = addYamlHeader(stringifyYaml(data), header);
    
    // Write with restricted permissions (owner read/write only)
    fs.writeFileSync(PERMISSION_FILE, yamlContent, { mode: 0o600 });
    _logDebug(`[PERMISSION] Saved permissions to: ${PERMISSION_FILE}`);
    return true;
  } catch (error) {
    _logError(`[PERMISSION] Failed to save permissions: ${error.message}`);
    return false;
  }
}

/**
 * Load tokens from YAML file (~/.pave/tokens.yaml)
 * Falls back to legacy .env files if YAML doesn't exist (with deprecation warning)
 * SECURITY: Values are stored in a private map, NOT in process.env
 * @param {boolean} force - Force reload even if file hasn't changed
 */
function loadTokensFile(force = false) {
  // Try new YAML format first
  if (fs.existsSync(TOKENS_FILE)) {
    return _loadTokensFromYaml(force);
  }
  
  // Fall back to legacy .env format with deprecation warning
  return _loadTokensFromLegacyEnv(force);
}

/**
 * Load tokens from new YAML format (~/.pave/tokens.yaml)
 * @private
 */
function _loadTokensFromYaml(force = false) {
  try {
    const stat = fs.statSync(TOKENS_FILE);
    const currentMtime = stat.mtimeMs;
    if (!force && TOKENS_FILE === _lastEnvFilePath && currentMtime === _lastEnvFileMtime) {
      return { loaded: true, path: TOKENS_FILE, count: 0, skipped: true };
    }
    
    const content = fs.readFileSync(TOKENS_FILE, 'utf8');
    const data = parseYaml(content);
    let loadedCount = 0;
    
    if (data && typeof data === 'object') {
      for (const [key, value] of Object.entries(data)) {
        if (typeof value === 'string') {
          _privateTokenValues.set(key, value);
          loadedCount++;
        }
      }
    }
    
    _lastEnvFilePath = TOKENS_FILE;
    _lastEnvFileMtime = currentMtime;
    
    if (loadedCount > 0) {
      _logDebug(`[PERMISSION] Loaded ${loadedCount} secure token values from: ${TOKENS_FILE}`);
    }
    
    return { loaded: true, path: TOKENS_FILE, count: loadedCount };
  } catch (error) {
    _logError(`[PERMISSION] Failed to load tokens file: ${error.message}`);
    return { loaded: false, path: TOKENS_FILE, count: 0, error: error.message };
  }
}

/**
 * Load tokens from legacy .env format (deprecated)
 * @private
 */
function _loadTokensFromLegacyEnv(force = false) {
  // Find first existing .env file
  let envPath = null;
  for (const testPath of LEGACY_ENV_FILE_PATHS) {
    try {
      if (fs.existsSync(testPath)) {
        envPath = testPath;
        break;
      }
    } catch (e) {
      // Ignore permission errors
    }
  }
  
  if (!envPath) {
    return { loaded: false, path: null, count: 0 };
  }
  
  // Show deprecation warning once per session
  if (!_shownDeprecationWarning.env) {
    _shownDeprecationWarning.env = true;
    _logWarn(`[PERMISSION] DEPRECATION WARNING: Using legacy .env file: ${envPath}`);
    _logWarn(`[PERMISSION] Please migrate your tokens to: ${TOKENS_FILE}`);
    _logWarn(`[PERMISSION] The new YAML format is simpler and more secure.`);
    _logWarn(`[PERMISSION] Example format:`);
    _logWarn(`[PERMISSION]   OPENAI_API_KEY: "sk-xxx..."`);
    _logWarn(`[PERMISSION]   GMAIL_CLIENT_ID: "xxx.apps.googleusercontent.com"`);
  }
  
  try {
    // Check if file has changed since last load (skip if unchanged)
    const stat = fs.statSync(envPath);
    const currentMtime = stat.mtimeMs;
    if (!force && envPath === _lastEnvFilePath && currentMtime === _lastEnvFileMtime) {
      // File hasn't changed, skip reload
      return { loaded: true, path: envPath, count: 0, skipped: true };
    }
    
    const envContent = fs.readFileSync(envPath, 'utf8');
    let loadedCount = 0;
    
    envContent.split('\n').forEach(line => {
      line = line.trim();
      // Skip empty lines and comments
      if (!line || line.startsWith('#')) return;
      
      // Must have = sign
      const eqIdx = line.indexOf('=');
      if (eqIdx === -1) return;
      
      const key = line.substring(0, eqIdx).trim();
      let value = line.substring(eqIdx + 1).trim();
      
      // Remove surrounding quotes if present
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      
      // SECURITY: Store in private map, NOT in process.env
      // This prevents token leakage to child processes (sandbox)
      // Always update value (may have changed in .env)
      _privateTokenValues.set(key, value);
      loadedCount++;
    });
    
    // Update mtime trackers
    _lastEnvFilePath = envPath;
    _lastEnvFileMtime = currentMtime;
    
    if (loadedCount > 0) {
      _logDebug(`[PERMISSION] Loaded ${loadedCount} secure token values from: ${envPath}`);
    }
    
    return { loaded: true, path: envPath, count: loadedCount, legacy: true };
  } catch (error) {
    _logError(`[PERMISSION] Failed to load .env file: ${error.message}`);
    return { loaded: false, path: envPath, count: 0, error: error.message };
  }
}

/**
 * Save tokens to YAML file (~/.pave/tokens.yaml)
 * SECURITY: Only saves if explicitly called (tokens aren't auto-saved)
 */
function saveTokensFile() {
  try {
    // Ensure directory exists
    if (!fs.existsSync(PAVE_DIR)) {
      fs.mkdirSync(PAVE_DIR, { recursive: true, mode: 0o700 });
    }
    
    // Convert private token values to object
    const tokensObj = {};
    for (const [key, value] of _privateTokenValues) {
      tokensObj[key] = value;
    }
    
    const header = `PAVE Tokens Configuration
Store your API keys and tokens here.
This file should have restricted permissions (chmod 600).

Example:
  OPENAI_API_KEY: "sk-xxx..."
  GMAIL_CLIENT_ID: "xxx.apps.googleusercontent.com"
  GMAIL_CLIENT_SECRET: "xxx"
  GMAIL_REFRESH_TOKEN: "xxx"`;
    
    const yamlContent = addYamlHeader(stringifyYaml(tokensObj), header);
    fs.writeFileSync(TOKENS_FILE, yamlContent, { mode: 0o600 });
    _logDebug(`[PERMISSION] Saved tokens to: ${TOKENS_FILE}`);
    return true;
  } catch (error) {
    _logError(`[PERMISSION] Failed to save tokens: ${error.message}`);
    return false;
  }
}

// Keep loadEnvFile as alias for backwards compatibility
const loadEnvFile = loadTokensFile;

/**
 * Load permissions from disk
 * Loads from ~/.pave/permissions.yaml (or falls back to legacy JSON)
 * @param {boolean} force - Force reload even if file hasn't changed
 */
function loadPermissions(force = false) {
  // First, try to load tokens file
  loadTokensFile();
  
  // Try new YAML format first
  if (fs.existsSync(PERMISSION_FILE)) {
    return _loadPermissionsFromYaml(force);
  }
  
  // Fall back to legacy JSON format with deprecation warning
  if (fs.existsSync(LEGACY_PERMISSION_FILE)) {
    return _loadPermissionsFromLegacyJson(force);
  }
  
  _logDebug(`[PERMISSION] No saved permissions found, using defaults`);
  return false;
}

/**
 * Load permissions from new YAML format (~/.pave/permissions.yaml)
 * @private
 */
function _loadPermissionsFromYaml(force = false) {
  try {
    // Check if file has changed since last load (skip if unchanged)
    const stat = fs.statSync(PERMISSION_FILE);
    const currentMtime = stat.mtimeMs;
    if (!force && currentMtime === _lastPermissionFileMtime) {
      return true;
    }
    
    const raw = fs.readFileSync(PERMISSION_FILE, 'utf8');
    const data = parseYaml(raw);
    
    // Validate version (support v1-v4)
    if (!data.version || ![1, 2, 3, 4].includes(data.version)) {
      _logWarn(`[PERMISSION] Unknown permission file version, using defaults`);
      return false;
    }
    
    return _applyPermissionData(data, currentMtime);
  } catch (error) {
    _logError(`[PERMISSION] Failed to load permissions: ${error.message}`);
    return false;
  }
}

/**
 * Load permissions from legacy JSON format (deprecated)
 * @private
 */
function _loadPermissionsFromLegacyJson(force = false) {
  // Show deprecation warning once per session
  if (!_shownDeprecationWarning.permissions) {
    _shownDeprecationWarning.permissions = true;
    _logWarn(`[PERMISSION] DEPRECATION WARNING: Using legacy JSON file: ${LEGACY_PERMISSION_FILE}`);
    _logWarn(`[PERMISSION] Please migrate your permissions to: ${PERMISSION_FILE}`);
    _logWarn(`[PERMISSION] The new YAML format is easier to edit and configure.`);
    _logWarn(`[PERMISSION] Run the server once with write permissions to auto-migrate.`);
  }
  
  try {
    // Check if file has changed since last load
    const stat = fs.statSync(LEGACY_PERMISSION_FILE);
    const currentMtime = stat.mtimeMs;
    if (!force && currentMtime === _lastPermissionFileMtime) {
      return true;
    }
    
    const raw = fs.readFileSync(LEGACY_PERMISSION_FILE, 'utf8');
    const data = JSON.parse(raw);
    
    // Validate version (support v1, v2, and v3)
    if (!data.version || ![1, 2, 3].includes(data.version)) {
      _logWarn(`[PERMISSION] Unknown permission file version, using defaults`);
      return false;
    }
    
    const result = _applyPermissionData(data, currentMtime);
    
    // Auto-migrate to new YAML format if we successfully loaded
    if (result) {
      _logInfo(`[PERMISSION] Auto-migrating permissions to YAML format...`);
      savePermissions();  // This will save in the new YAML format
    }
    
    return result;
  } catch (error) {
    _logError(`[PERMISSION] Failed to load legacy permissions: ${error.message}`);
    return false;
  }
}

/**
 * Apply loaded permission data to in-memory structures
 * @private
 */
function _applyPermissionData(data, mtime) {
  const p = data.permissions;
  if (!p) {
    _logWarn(`[PERMISSION] Invalid permission file format, using defaults`);
    return false;
  }
  
  // Restore permissions from saved data
  // SECURITY: Default to empty sets (deny by default) - never fall back to '*'
  permissions.network = new Set(p.network || []);
  permissions.filesystem.read = new Set(p.filesystem?.read || []);
  permissions.filesystem.write = new Set(p.filesystem?.write || []);
  permissions.modules = new Set(p.modules || ['*']);
  // System commands: use saved value if provided, otherwise keep default safe commands
  permissions.system = new Set(p.system || DEFAULT_SYSTEM_COMMANDS);
  
  // Load skill permissions (v3+)
  // Default: allow all skills (for backward compatibility)
  permissions.skills.allowed = new Set(p.skills?.allowed || ['*']);
  permissions.skills.denied = new Set(p.skills?.denied || []);
  
  // Load token configurations (v2+)
  if (data.tokens && typeof data.tokens === 'object') {
    tokenConfigs.clear();
    for (const [name, config] of Object.entries(data.tokens)) {
      try {
        // Re-register to validate
        registerToken(name, config);
      } catch (err) {
        _logWarn(`[PERMISSION] Skipping invalid token config '${name}': ${err.message}`);
      }
    }
    _logDebug(`[PERMISSION] Loaded ${tokenConfigs.size} token configurations`);
  }
  
  // Update mtime tracker
  _lastPermissionFileMtime = mtime;
  
  _logDebug(`[PERMISSION] Loaded permissions from: ${PERMISSION_FILE}`);
  _logDebug(`[PERMISSION] Last saved: ${data.savedAt || 'unknown'}`);
  return true;
}

/**
 * Get the permission file path (for debugging/info)
 */
function getPermissionFilePath() {
  return PERMISSION_FILE;
}

/**
 * Get the tokens file path (for debugging/info)
 */
function getTokensFilePath() {
  return TOKENS_FILE;
}

/**
 * Get all configuration file paths (for debugging/info)
 */
function getConfigPaths() {
  return {
    paveDir: PAVE_DIR,
    tokensFile: TOKENS_FILE,
    permissionsFile: PERMISSION_FILE,
    legacyPermissionsFile: LEGACY_PERMISSION_FILE,
    legacyEnvPaths: LEGACY_ENV_FILE_PATHS
  };
}

/**
 * Format permission result for display
 */
function formatPermissionOutput(result) {
  if (!result.success) {
    return `Error: ${result.error}`;
  }
  
  let output = result.message + '\n';
  
  if (result.action === 'list' && result.permissions) {
    const p = result.permissions;
    output += '\nNetwork: ' + (p.network?.length > 0 ? p.network.join(', ') : '(none)');
    output += '\nFile Read: ' + (p.filesystem?.read?.length > 0 ? p.filesystem.read.join(', ') : '(none)');
    output += '\nFile Write: ' + (p.filesystem?.write?.length > 0 ? p.filesystem.write.join(', ') : '(none)');
    output += '\nModules: ' + (p.modules?.length > 0 ? p.modules.join(', ') : '(none)');
    output += '\nSystem: ' + (p.system?.length > 0 ? p.system.join(', ') : '(none)');
    output += '\nSkills Allowed: ' + (p.skills?.allowed?.length > 0 ? p.skills.allowed.join(', ') : '(none)');
    output += '\nSkills Denied: ' + (p.skills?.denied?.length > 0 ? p.skills.denied.join(', ') : '(none)');
  }
  
  if (result.pending) {
    output += '\n\nThis request requires user confirmation.';
    output += `\nRequest ID: ${result.requestId}`;
  }
  
  return output;
}

// Load saved permissions on module initialization
_ensurePermissionsLoaded();

module.exports = {
  executePermission,
  confirmPermissionRequest,
  denyPermissionRequest,
  getPendingRequest,
  getAllPendingRequests,
  cleanupOldRequests,
  formatPermissionOutput,
  CONFIRMATION_REQUIRED_ACTIONS,
  DEFAULT_SYSTEM_COMMANDS,
  // Logging control
  setLogLevel,
  getLogLevel,
  // Direct access for internal use
  checkPermission,
  listPermissions,
  // Direct grant/revoke for CLI use
  grantPermission,
  revokePermission,
  clearPermissions,
  // Persistence functions
  savePermissions,
  loadPermissions,
  loadEnvFile,
  loadTokensFile,
  saveTokensFile,
  getPermissionFilePath,
  getTokensFilePath,
  getConfigPaths,
  // Token management (public)
  registerToken,
  unregisterToken,
  hasToken,
  listTokens,
  getTokenConfig,
  isTokenDomainAllowed,
  logTokenUsage,
  getTokenAuditLog,
  // Token internals (for IPC bridge only - not for sandbox)
  _getTokenValue,
  _getRefreshTokenValue,
  _getOAuthClientCredentials,
  _buildTokenInjection,
  _refreshOAuthToken,
  _buildOAuthRefreshConfig,
  // Skill permission checking
  checkSkillPermission,
  skillPatternMatches
};
