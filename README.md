# ⚡ PortX

> **Scan Hard. Scan Fast. Dominate the Network.**

PortX is an aggressive, high-performance multi-threaded TCP/UDP port scanner built in Python for security researchers, ethical hackers, and network professionals.

Designed to tear through all 65,535 ports with speed and stability, PortX combines DNS resolution, batch-based threading, service detection, and real-time progress tracking into one powerful reconnaissance tool.

---

## 🚀 Features

- ⚡ High-speed multi-threaded scanning
- 🔍 Full port range scanning (1–65535)
- 🔁 TCP and UDP support
- 🌐 Bulk domain resolution from file
- 📊 Real-time progress bar (tqdm)
- 🎨 Colored CLI output (colorama)
- 🧠 Automatic service detection
- 📁 Structured output logging
- 🛑 Graceful shutdown with CTRL + C

---

## 🛠 Installation

### 1️⃣ Clone Repository

```bash
git clone https://github.com/jake741/PortX.git
cd PortX
```
### 2️⃣ Install Requirements

```bash
pip install tqdm colorama
```
### ▶ Usage
```bash
python3 scanner.py targets.txt
```

### Example targets.txt
```bash
example.com
scanme.nmap.org
8.8.8.8
```
### ⚙ Configuration

You can modify performance settings inside the script:
```bash
MAX_THREADS = 300
TIMEOUT = 0.5
START_PORT = 1
END_PORT = 65535
BATCH_SIZE = 2000
SCAN_TCP = True
SCAN_UDP = True
```
Adjust based on your hardware and network capacity.

### 📂 Output

Results are saved to:
```bash
scan_results.txt
```
Each scan report includes:

- Resolved IP

- Associated domains

- Open TCP ports

- Open UDP ports

- Detected services

- Total open ports

- Scan timestamp

### ⚠ Legal Disclaimer

This tool is intended for:

- Educational use

- Lab environments

- Authorized penetration testing

Do NOT scan networks or systems without explicit permission.

The author is not responsible for misuse.

### 👨‍💻 Author

Jake
GitHub: https://github.com/jake741
