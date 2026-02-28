# PAVE Distribution

Pre-compiled binaries for [PAVE](https://github.com/cnrai/openpave) - Personal AI Virtual Environment.

---

## 🍎 macOS Installation

### Option 1: Homebrew (Recommended)

```bash
brew tap cnrai/tap
brew install pave
```

**Upgrade to latest version:**
```bash
brew update && brew upgrade pave
```

### Option 2: Direct Download

**Apple Silicon (M1/M2/M3/M4):**
```bash
curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-darwin-arm64 -o /usr/local/bin/pave && chmod +x /usr/local/bin/pave
```

**Intel Mac:**
```bash
curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-darwin-x64 -o /usr/local/bin/pave && chmod +x /usr/local/bin/pave
```

---

## 🐧 Linux Installation

### One-Liner (System-wide)

```bash
sudo curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-x64 -o /usr/local/bin/pave && sudo chmod +x /usr/local/bin/pave
```

### Without sudo (User Install)

```bash
mkdir -p ~/.local/bin && \
curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-x64 -o ~/.local/bin/pave && \
chmod +x ~/.local/bin/pave && \
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && \
source ~/.bashrc
```

### Docker

```bash
docker run --platform linux/amd64 -it ubuntu:22.04 bash -c "\
  apt update && apt install -y curl && \
  curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-x64 -o /usr/local/bin/pave && \
  chmod +x /usr/local/bin/pave && \
  pave --version"
```

---

## ✅ Verify Installation

```bash
pave --version
```

Expected output:
```
PAVE version 0.3.15
```

---

## 🚀 Quick Start

```bash
# Start a chat
pave chat "Hello, what can you do?"

# Run with a skill
pave run gmail unread

# Get help
pave --help
```

---

## 🔧 Optional: SpiderMonkey (for Sandboxed Execution)

PAVE uses SpiderMonkey for secure code sandboxing. Install it for full functionality:

**macOS:**
```bash
brew install spidermonkey
```

**Ubuntu/Debian:**
```bash
sudo apt install -y libmozjs-91-dev
sudo ln -sf /usr/bin/js91 /usr/local/bin/js
```

**Alpine Linux:**
```bash
apk add spidermonkey
```

---

## 📦 Available Binaries

| Platform | Architecture | Download |
|----------|--------------|----------|
| macOS | ARM64 (M1/M2/M3/M4) | [pave-darwin-arm64](https://github.com/cnrai/pave-dist/releases/latest/download/pave-darwin-arm64) |
| macOS | x64 (Intel) | [pave-darwin-x64](https://github.com/cnrai/pave-dist/releases/latest/download/pave-darwin-x64) |
| Linux | x64 | [pave-linux-x64](https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-x64) |

---

## 🗑️ Uninstall

**Homebrew:**
```bash
brew uninstall pave
brew untap cnrai/tap
```

**Direct install:**
```bash
rm /usr/local/bin/pave
# or
rm ~/.local/bin/pave
```

---

## 🔗 Links

- **Main Repository**: [cnrai/openpave](https://github.com/cnrai/openpave)
- **All Releases**: [Releases](https://github.com/cnrai/pave-dist/releases)
- **Report Issues**: [Issues](https://github.com/cnrai/openpave/issues)
- **Homebrew Tap**: [cnrai/homebrew-tap](https://github.com/cnrai/homebrew-tap)
