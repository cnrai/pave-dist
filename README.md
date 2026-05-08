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

### Linux x64 (Intel/AMD)

**One-Liner (System-wide):**
```bash
sudo curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-x64 -o /usr/local/bin/pave && sudo chmod +x /usr/local/bin/pave
```

**Without sudo (User Install):**
```bash
mkdir -p ~/.local/bin && \
curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-x64 -o ~/.local/bin/pave && \
chmod +x ~/.local/bin/pave && \
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && \
source ~/.bashrc
```

### Linux ARM64 (Raspberry Pi, AWS Graviton, NVIDIA Jetson, Ampere)

**One-Liner (System-wide):**
```bash
sudo curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-arm64 -o /usr/local/bin/pave && sudo chmod +x /usr/local/bin/pave
```

**Without sudo (User Install):**
```bash
mkdir -p ~/.local/bin && \
curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-arm64 -o ~/.local/bin/pave && \
chmod +x ~/.local/bin/pave && \
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && \
source ~/.bashrc
```

### NVIDIA DGX (Grace Hopper / Grace ARM64)

NVIDIA DGX systems built on Grace CPUs (GH200, GB200) and DGX Spark run Linux ARM64. Install the ARM64 binary directly — the same binary used for Graviton/Jetson works without modification:

```bash
sudo curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-arm64 -o /usr/local/bin/pave && \
sudo chmod +x /usr/local/bin/pave && \
pave --version
```

**Verify your DGX is ARM64:**
```bash
uname -m   # should print: aarch64
```

If `uname -m` returns `x86_64` (older DGX A100/H100 Intel-based systems), use the Linux x64 install above instead.

**Optional — SpiderMonkey for sandboxed execution:**
```bash
sudo apt install -y libmozjs-91-dev
sudo ln -sf /usr/bin/js91 /usr/local/bin/js
```

### Docker

**linux/amd64:**
```bash
docker run --platform linux/amd64 -it ubuntu:22.04 bash -c "\
  apt update && apt install -y curl && \
  curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-x64 -o /usr/local/bin/pave && \
  chmod +x /usr/local/bin/pave && \
  pave --version"
```

**linux/arm64 (DGX, Apple Silicon hosts, Graviton):**
```bash
docker run --platform linux/arm64 -it ubuntu:22.04 bash -c "\
  apt update && apt install -y curl && \
  curl -fsSL https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-arm64 -o /usr/local/bin/pave && \
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
| Linux | ARM64 (Pi, Graviton, Jetson, NVIDIA DGX Grace) | [pave-linux-arm64](https://github.com/cnrai/pave-dist/releases/latest/download/pave-linux-arm64) |

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
