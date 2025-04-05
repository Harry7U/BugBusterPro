# 🛡️ BugBusterPro 🐛

<div align="center">
  
![BugBusterPro Logo](https://imgur.com/placeholder/400/150)

**All-in-One Bug Bounty Automation Tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Made%20with-Bash-1f425f.svg)](https://www.gnu.org/software/bash/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

</div>

## 🌟 Features

BugBusterPro is a comprehensive, automated bug bounty hunting tool designed to streamline the reconnaissance and vulnerability discovery process for security researchers.

- 🔍 **Subdomain Enumeration** - Discover all subdomains using multiple sources
- 🌐 **URL Collection** - Gather URLs from various sources including Wayback Machine
- 🔐 **Secret Files Discovery** - Find potentially sensitive files and data
- 📜 **JavaScript Reconnaissance** - Extract and analyze JavaScript files
- 🗂️ **Directory Bruteforce** - Discover hidden directories and files
- ⚠️ **XSS Scanning** - Detect cross-site scripting vulnerabilities
- 🏗️ **Subdomain Takeover** - Check for potential subdomain takeover opportunities
- 🔄 **CORS Misconfiguration** - Find cross-origin resource sharing issues
- 🚨 **CVE Scanning** - Detect known vulnerabilities using nuclei templates
- 📊 **Automated Reporting** - Generate comprehensive markdown reports

## 📋 Requirements

- Linux-based operating system
- Bash 4+
- Go 1.16+
- Python 3.6+
- Internet connection to install dependencies

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Harry7U/BugBusterPro.git

# Navigate to the directory
cd BugBusterPro

# Make the script executable
chmod +x bugbusterpro.sh

# Run the script (dependencies will be installed automatically)
./bugbusterpro.sh --domain example.com
```

## 💻 Usage

```
Usage:
  ./bugbusterpro.sh --domain <target> [options]

Required Arguments:
  --domain <target>     Target domain to scan

Options:
  --output-dir <dir>    Output directory (default: ./bugbusterpro_output)
  --force               Force rerun of all steps even if output exists
  --threads <num>       Number of threads to use (default: 50)
  --silent              Run in silent mode (less verbose output)
  --no-banner           Don't display the banner
  --help                Show this help message and exit
  --version             Show version information

Example:
  ./bugbusterpro.sh --domain example.com --output-dir ./results --threads 100
```

## 🔄 Workflow

1. **Dependency Installation** - Automatically installs all required tools
2. **Subdomain Discovery** - Uses subfinder to find all related subdomains
3. **Subdomain Probing** - Identifies alive hosts with httpx
4. **URL Collection** - Gathers URLs from multiple sources
5. **Secret Files Discovery** - Identifies potential sensitive files
6. **JavaScript Reconnaissance** - Analyzes JavaScript for vulnerabilities
7. **Directory Bruteforce** - Discovers hidden directories and files
8. **XSS Scanning** - Checks for cross-site scripting vulnerabilities
9. **Subdomain Takeover Check** - Identifies potential takeover opportunities
10. **CORS Scanner** - Finds CORS misconfigurations
11. **Misconfig Scan** - Detects security misconfigurations
12. **CVE Scanning** - Identifies known vulnerabilities
13. **LFI Testing** - Tests for Local File Inclusion vulnerabilities
14. **Report Generation** - Creates a comprehensive markdown report

## 📊 Sample Output

```
[2023-08-10 15:32:18] [INFO] Installing required system packages...
[2023-08-10 15:34:05] [SUCCESS] All dependencies installed successfully
[2023-08-10 15:34:05] [STEP] Creating directory structure...
[2023-08-10 15:34:06] [SUCCESS] Directory structure created: ./bugbusterpro_output
[2023-08-10 15:34:06] [STEP] Running subdomain discovery for example.com...
[2023-08-10 15:36:25] [SUCCESS] Subdomain discovery completed. Found 127 subdomains.
...
[2023-08-10 16:22:45] [SUCCESS] BugBusterPro scan completed for example.com
[2023-08-10 16:22:45] [INFO] Report available at: ./bugbusterpro_output/BugBusterPro_Report.md
```

## 📝 Report Format

The tool generates a comprehensive markdown report that includes:

- **Summary statistics** - Subdomains, alive hosts, URLs, etc.
- **Potential findings** - Organized by vulnerability type
- **Subdomain takeover vulnerabilities**
- **CORS misconfigurations**
- **Secret files**
- **XSS vulnerabilities**
- **JavaScript security issues**
- **Security misconfigurations**
- **CVE findings**
- **LFI vulnerabilities**

## 🛠️ Tools Used

BugBusterPro automates the installation and usage of the following tools:

- subfinder - For subdomain discovery
- httpx - For probing and analyzing HTTP responses
- katana - For crawling and gathering endpoints
- waybackurls - For fetching URLs from Wayback Machine
- otxurls - For collecting URLs from AlienVault's OTX
- feroxbuster - For directory bruteforcing
- nuclei - For template-based scanning
- subzy - For subdomain takeover checks
- qsreplace - For query string replacement
- gf - For pattern matching
- bxss - For blind XSS testing
- Corsy - For CORS misconfiguration testing

## 🤝 Contributing

Contributions are welcome! Feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is intended for security professionals and bug bounty hunters to use on authorized targets only. The author is not responsible for any misuse or damage caused by this program. Always ensure you have explicit permission to test the target systems.

## 👤 Author

**Harry7U**

- GitHub: [Harry7U](https://github.com/Harry7U)

## 🌟 Acknowledgements

- All the amazing open-source security tools this project depends on
- The bug bounty community for continuous inspiration and knowledge sharing

---

<div align="center">
  
Made with ❤️ for the bug bounty community

</div>
