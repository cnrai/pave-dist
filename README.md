# PAVE Distribution

Pre-compiled distribution of PAVE (Personal AI Virtual Environment).

This repository contains the compiled, ready-to-run version of PAVE for easy installation via Homebrew or direct download.

## Installation

### Via Homebrew (Recommended)

```bash
brew tap cnrai/tap
brew install pave
```

### Manual Installation

```bash
# Download the latest release
curl -sL https://github.com/cnrai/pave-dist/archive/refs/tags/v0.2.0.tar.gz | tar xz
cd pave-dist-0.2.0

# Install dependencies
npm install --production

# Run directly
node pave.js

# Or link globally
npm link
```

## Requirements

- Node.js 16 or higher

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

## License

MIT License

## Links

- Homepage: https://github.com/cnrai/openpave
- Issues: https://github.com/cnrai/openpave/issues
