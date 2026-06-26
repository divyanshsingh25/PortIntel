# 🔍 PortIntel

Autonomous Port Scanner & Network Reconnaissance Tool built in Python.
This is a final project of internship at VOIS.

A modular, multi-threaded scanner with service detection, banner grabbing, OS fingerprinting, and a real-time Flask dashboard.

> ⚠️ Use only on systems you own or have explicit permission to test.


## 🚀 Quick Start

### 1. Install dependency (for dashboard)

```bash
## 🚀 Installation

```bash
pip install -r requirements.txt
```

```

### 2. Run CLI Scanner

```bash
python run_scanner.py 192.168.1.1
```

Scan custom ports:

```bash
python run_scanner.py example.com -p 80,443,8080 --json --txt
```

### 3. Launch Web Dashboard

```bash
python run_dashboard.py
```

Open: http://127.0.0.1:5000

---

## ✨ Features

* Multi-threaded TCP port scanning
* Banner grabbing & service detection
* Version detection (regex-based)
* OS fingerprinting (TTL-based)
* Supports IP, domain, CIDR, and ranges
* JSON & TXT export
* Real-time Flask dashboard (charts + history)
* Logging system (file + console)

---

## 📁 Project Structure

```
port_scanner/
│── scanner.py
│── utils.py
│── reporter.py
│── cli.py
│── dashboard.py
│── logger.py
│── config.py

run_scanner.py
run_dashboard.py
```

---

## ⚠️ Disclaimer

This tool is for educational and authorized security testing only.
The author is not responsible for misuse or unauthorized scanning.

---

## 📄 License

MIT License © 2026 Divyansh Singh
