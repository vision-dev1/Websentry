# WebSentry 🛡️

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)

## Overview

**WebSentry** is a lightweight, comprehensive web application vulnerability scanner designed for ethical security testing. It combines a robust Python backend for scanning logic with a responsive HTML/JS frontend for an intuitive user experience.

> **⚠️ Disclaimer**: This tool is for **EDUCATIONAL PURPOSES AND ETHICAL TESTING ONLY**. Use this tool only on systems you own or have explicit permission to test. The developers assume no liability for misuse.

## Features

- **Vulnerability Detection**: Scans for common web vulnerabilities including:
  - Cross-Site Scripting (Reflected & Stored XSS)
  - SQL Injection (SQLi)
  - Open Redirects
  - Local File Inclusion (LFI)
  - Exposed Sensitive Files (git, env, backups)
- **Security Header Analysis**: Checks for missing or misconfigured HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).
- **Interactive Reports**: Generates detailed JSON logs and displays real-time scan results in the dashboard.
- **Cross-Platform**: Runs seamlessly on Linux, Windows, and macOS.

## Project Structure

```
WebSentry/
├── index.html          # Main dashboard interface
├── script.js           # Frontend logic and API communication
├── styles.css          # Custom styling
├── scanner.py          # Python backend server and scanning engine
├── run.sh              # Linux/Mac launch script
├── run.bat             # Windows launch script
├── requirements.txt    # Python dependencies
└── scan_logs/          # Directory for saved scan reports
```

## Installation

### Prerequisites
- **Python 3.8+**
- **pip** (Python package manager)
- A modern web browser

### Setup

1. **Clone the repository** (or download source):
   ```bash
   git clone https://github.com/vision-dev1/Websentry.git
   cd Websentry
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### On Linux/macOS
Make the script executable and run it:
```bash
chmod +x run.sh
./run.sh
```

### On Windows
Double-click `run.bat` or run via command prompt:
```cmd
run.bat
```

### Manual Start
1. Start the Python backend:
   ```bash
   python scanner.py
   ```
2. Open `index.html` in your browser (or follow the URL provided by the backend, usually `http://localhost:5000` or file-based access depending on configuration).

## Visuals

The interface features a modern, dark-themed design with real-time progress indicators, severity coding (High/Medium/Low), and exportable reports.

## License

MIT License - see the LICENSE file for details.
