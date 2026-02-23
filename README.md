# PAVE Distribution

Pre-compiled, obfuscated distribution of PAVE (Personal AI Virtual Environment).

This repository contains the **compiled native binary** for easy installation via Homebrew or direct download. The source code has been obfuscated to protect the sandbox implementation.

## Installation

### Via Homebrew (Recommended)

```bash
brew tap cnrai/tap
brew install pave
```

### Manual Installation

1. **Download the release for your platform:**
   - macOS Apple Silicon: `pave-darwin-arm64`
   - macOS Intel: `pave-darwin-x64` 
   - Linux x64: `pave-linux-x64`

2. **Make it executable:**
   ```bash
   chmod +x pave-darwin-arm64
   ```

3. **Run:**
   ```bash
   ./pave-darwin-arm64 --help
   ```

## Requirements

- **SpiderMonkey**: `brew install spidermonkey` (for sandbox execution)
- **macOS 11+** or **Linux** with glibc 2.17+

## Usage

```bash
# Start the Terminal UI
pave

# Non-interactive chat
pave chat "Hello, how are you?"

# Run skill commands  
pave run gmail list --max 5

# Manage skills
pave install gmail
pave list
pave search email
```

## Configuration

Set the `OPENCODE_URL` environment variable to point to your AI backend:

```bash
export OPENCODE_URL=http://localhost:4096
pave
```

## Files Included

- `pave-*` - Native executable for each platform
- `sandbox/` - Sandbox runner components for secure code execution

## Security

- Source code is **obfuscated** to protect the sandbox implementation
- Sandbox execution runs in **isolated SpiderMonkey compartments**
- All sensitive strings are **encoded** and not readable in the binary

## License

MIT License

## Links

- Homepage: https://github.com/cnrai/openpave
- Issues: https://github.com/cnrai/openpave/issues
- Homebrew Tap: https://github.com/cnrai/homebrew-tap