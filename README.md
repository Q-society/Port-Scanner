# QSOC-Scanner

**Enterprise-style desktop console for TCP/UDP port reconnaissance — IPv4 & IPv6, with banner-based service detection and risk scoring.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![PyQt5](https://img.shields.io/badge/GUI-PyQt5-41CD52?style=flat-square&logo=qt&logoColor=white)](https://pypi.org/project/PyQt5/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-555555?style=flat-square)](#installation)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](#license)
[![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)]()

QSOC-Scanner is a standalone GUI application — not a terminal script — for scanning the full TCP/UDP port range on a target host. It identifies live services from real banner data where possible, falls back to a curated port-intelligence table otherwise, and flags each finding with a risk level so you can triage results at a glance.

<p align="center">
  <img src="https://img.shields.io/badge/-●%20LIVE%20SCAN%20CONSOLE-0d1117?style=for-the-badge&labelColor=141a23&color=4c8dff" alt="banner"/>
</p>

---

## Features

| | |
|---|---|
| 🖥️ **Standalone GUI** | Opens as its own desktop window with a splash screen — no terminal output to read |
| 🌐 **IPv4 & IPv6** | Auto-detects target address family, or force one explicitly |
| 🔀 **TCP / UDP / Both** | Select scan protocol from a dropdown — run either or both in one pass |
| 🔍 **Service fingerprinting** | Matches live banners (SSH, HTTP server headers, MySQL, Redis, VNC, MongoDB, etc.) instead of relying on port number alone |
| ⚠️ **Risk scoring** | Every open port is labeled LOW / MEDIUM / HIGH / CRITICAL with a short remediation note |
| ⚡ **Multi-threaded** | Configurable worker count for fast full-range (1–65535) scans |
| 📄 **One-click export** | Save results as a clean, formatted `.txt` report |
| 🎛️ **Scan presets** | Full range, well-known ports (1–1023), or common services |

---

## Screenshots

> Run the app locally to see it live — the interface uses a dark, neutral slate theme designed for SOC/NOC-style monitoring, not a "hacker terminal" aesthetic.

```
┌─────────────────────────────────────────────────────────┐
│  QSOC-Scanner                    [ AUTHORIZED TARGETS ]  │
│  Enterprise Port Reconnaissance Console                  │
├─────────────────────────────────────────────────────────┤
│  TARGET CONFIGURATION                                     │
│  Target: [ 192.168.1.10                              ]   │
│  IP version: [Auto-detect▾]   Protocol: [TCP▾]            │
│  Ports: [1] – [65535]         Preset: [Full range▾]       │
│  Threads: [200]   Timeout: [0.5s]                          │
│  ☑ I confirm I own this target or have authorization      │
│                                                             │
│  [ ▶ Start Scan ]  [ ■ Stop ]            [ ⤓ Export ]      │
└─────────────────────────────────────────────────────────┘
```

---

## ⚠️ Legal & Ethical Use

This tool performs **active network connection attempts** against a target host. Only scan:

- Systems **you personally own**, or
- Systems you have **explicit written authorization** to test (e.g. a signed penetration testing engagement letter).

Unauthorized scanning of third-party systems may violate laws such as the U.S. Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, or equivalent legislation in your country — even when no exploitation is attempted. The in-app authorization checkbox is a reminder, not a legal safeguard. **You are responsible for how you use this tool.**

---

## Requirements

- **Python 3.8 or newer**
- **PyQt5**

No other dependencies — the scan engine itself uses only the Python standard library (`socket`, `threading`, `queue`).

---

## Installation

Pick the instructions for your operating system. All of them end with the same final step: `python scanport.py` (or `python3 scanport.py`).

### 🪟 Windows

```powershell
# 1. Clone the repository
git clone https://github.com/Q-society/Port-Scanner.git
cd Port-Scanner

# 2. (Optional but recommended) create a virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install PyQt5

# 4. Run
python scanport.py
```

### 🍎 macOS

```bash
# 1. Clone the repository
git clone https://github.com/Q-society/Port-Scanner.git
cd Port-Scanner

# 2. (Optional but recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip3 install PyQt5

# 4. Run
python3 scanport.py
```

### 🐧 Linux (Debian / Ubuntu / Kali)

```bash
# 1. Clone the repository
git clone https://github.com/Q-society/Port-Scanner.git
cd Port-Scanner

# 2. Install PyQt5 (system package is usually the smoothest route)
sudo apt update
sudo apt install python3-pyqt5 -y

# 3. Run
python3 scanport.py
```

### 🐧 Linux (Fedora / RHEL / CentOS)

```bash
git clone https://github.com/Q-society/Port-Scanner.git
cd Port-Scanner

sudo dnf install python3-qt5 -y
python3 scanport.py
```

### 🐧 Linux (Arch)

```bash
git clone https://github.com/Q-society/Port-Scanner.git
cd Port-Scanner

sudo pacman -S python-pyqt5
python3 scanport.py
```

### 📦 Any platform, via pip (alternative to system packages)

If your distro's PyQt5 package is missing or outdated, pip works everywhere:

```bash
git clone https://github.com/Q-society/Port-Scanner.git
cd Port-Scanner
pip install -r requirements.txt
python scanport.py
```

---

## Usage

1. Launch the app — a brief splash screen appears, then the main console opens.
2. Enter a **target**: an IPv4 address, an IPv6 address, or a hostname.
3. Choose **IP version** (Auto-detect is fine for almost everyone) and **Protocol** (TCP, UDP, or Both).
4. Pick a **port range** or a preset (Full range / Well-known / Common services).
5. Tick the **authorization checkbox** — required before scanning will start.
6. Click **Start Scan**. Results stream into the table as ports are found open; the activity log on the right shows live progress.
7. Click **Export Report** to save a timestamped `.txt` summary.

### Tuning scan speed

- **Threads**: higher = faster, but more aggressive on the network. `200` is a sensible default for a local network target.
- **Timeout**: lower (e.g. `0.2s`) speeds up scans on low-latency networks but may miss slow-to-respond services. Raise it for scans over the internet or against hosts behind a firewall that silently drops packets.
- A full 1–65535 TCP scan against a responsive LAN host typically completes in a few minutes at default settings.

---

## How service detection works

QSOC-Scanner doesn't just guess from the port number. For every open TCP port, it grabs whatever banner the service sends back and checks it against a set of known signatures — for example, an `SSH-2.0-OpenSSH_8.9p1` banner is parsed into `OpenSSH 8.9p1`, and an HTTP `Server: nginx/1.18.0` header becomes `nginx 1.18.0`. When no banner is available or recognized, it falls back to a curated table of ~40 well-known ports with sensible defaults (e.g. port 3389 → RDP → CRITICAL).

UDP works differently since there's no handshake: a probe is sent, and a response (or, for well-known UDP services, the absence of an ICMP "port unreachable" error) is reported as **open** or **open|filtered**, clearly labeled as unconfirmed when no direct response was received — UDP scanning is inherently less precise than TCP.

---

## Roadmap / ideas for contributions

- [ ] JSON / CSV export alongside the existing `.txt` report
- [ ] Optional `nmap -sV` handoff for deeper service/version fingerprinting on discovered ports
- [ ] Scan history with diffing between runs against the same target
- [ ] Custom port-list import (e.g. from a file)

Pull requests welcome — please keep new features behind the existing authorization-checkbox gate.

---

## License

MIT — see [`LICENSE`](LICENSE) for details.

---

## Disclaimer

This software is provided for educational and authorized security-testing purposes only. The author(s) are not responsible for misuse. Always obtain proper authorization before scanning any network or system you do not own.
