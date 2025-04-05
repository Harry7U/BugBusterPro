# BugBusterPro 🛡️🐛

<div align="center">
  

![bugbusterpro-logo](https://github.com/user-attachments/assets/ccc05af9-28d2-4322-a7ce-1bac4cbff3e2)


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Made%20with-Bash-1f425f.svg)](https://www.gnu.org/software/bash/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
![GitHub stars](https://img.shields.io/github/stars/Harry7U/BugBusterPro?style=social)
![GitHub forks](https://img.shields.io/github/forks/Harry7U/BugBusterPro?style=social)

</div>

<div align="center">
  
</div>

## ✨ Features

BugBusterPro is a comprehensive, automated bug bounty hunting tool designed to streamline the reconnaissance and vulnerability discovery process for security researchers.

<table>
  <tr>
    <td>🔍 <b>Subdomain Enumeration</b></td>
    <td>Discover all subdomains using multiple sources</td>
  </tr>
  <tr>
    <td>🌐 <b>URL Collection</b></td>
    <td>Gather URLs from various sources including Wayback Machine</td>
  </tr>
  <tr>
    <td>🔐 <b>Secret Files Discovery</b></td>
    <td>Find potentially sensitive files and data</td>
  </tr>
  <tr>
    <td>📜 <b>JavaScript Reconnaissance</b></td>
    <td>Extract and analyze JavaScript files</td>
  </tr>
  <tr>
    <td>🗂️ <b>Directory Bruteforce</b></td>
    <td>Discover hidden directories and files</td>
  </tr>
  <tr>
    <td>⚠️ <b>XSS Scanning</b></td>
    <td>Detect cross-site scripting vulnerabilities</td>
  </tr>
  <tr>
    <td>🏗️ <b>Subdomain Takeover</b></td>
    <td>Check for potential subdomain takeover opportunities</td>
  </tr>
  <tr>
    <td>🔄 <b>CORS Misconfiguration</b></td>
    <td>Find cross-origin resource sharing issues</td>
  </tr>
  <tr>
    <td>🚨 <b>CVE Scanning</b></td>
    <td>Detect known vulnerabilities using nuclei templates</td>
  </tr>
  <tr>
    <td>📊 <b>Automated Reporting</b></td>
    <td>Generate comprehensive markdown reports</td>
  </tr>
</table>

## 🚀 Installation

<div align="center">
  
</div>

```bash
# Clone the repository
git clone https://github.com/Harry7U/BugBusterPro.git

# Navigate to the directory
cd BugBusterPro

# Make the script executable
chmod +x BugBusterPro.sh

# Run the script (dependencies will be installed automatically)
./BugBusterPro.sh --domain example.com
```

## 💻 Usage

<div align="center">
  
</div>

```
Usage:
  ./BugBusterPro.sh --domain <target> [options]

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
  ./BugBusterPro.sh --domain example.com --output-dir ./results --threads 100
```

## 🔄 Workflow

<div align="center">
  
</div>

1. 📥 **Dependency Installation** - Automatically installs all required tools
2. 🔎 **Subdomain Discovery** - Uses subfinder to find all related subdomains
3. 🔍 **Subdomain Probing** - Identifies alive hosts with httpx
4. 🕸️ **URL Collection** - Gathers URLs from multiple sources
5. 🔒 **Secret Files Discovery** - Identifies potential sensitive files
6. 📝 **JavaScript Reconnaissance** - Analyzes JavaScript for vulnerabilities
7. 📂 **Directory Bruteforce** - Discovers hidden directories and files
8. 🛡️ **XSS Scanning** - Checks for cross-site scripting vulnerabilities
9. 🚩 **Subdomain Takeover Check** - Identifies potential takeover opportunities
10. 🔀 **CORS Scanner** - Finds CORS misconfigurations
11. ⚙️ **Misconfig Scan** - Detects security misconfigurations
12. 🔍 **CVE Scanning** - Identifies known vulnerabilities
13. 📁 **LFI Testing** - Tests for Local File Inclusion vulnerabilities
14. 📋 **Report Generation** - Creates a comprehensive markdown report

## 📊 Sample Output

<div align="center">

![image](https://github.com/user-attachments/assets/3018971c-e130-4b17-aba8-3ab0f2dcd7ff)
![image](https://github.com/user-attachments/assets/d4a8a56c-5cd1-40ec-ac2b-a0d08c8e9069)
![image](https://github.com/user-attachments/assets/ba54af27-8039-458c-9f2a-e1726531e7d2)

</div>

## 📝 Report Format

<div align="center">
  
</div>

The tool generates a comprehensive markdown report that includes:

- 📊 **Summary statistics** - Subdomains, alive hosts, URLs, etc.
- 🚨 **Potential findings** - Organized by vulnerability type
- 🏗️ **Subdomain takeover vulnerabilities**
- 🔄 **CORS misconfigurations**
- 🔐 **Secret files**
- ⚠️ **XSS vulnerabilities**
- 📜 **JavaScript security issues**
- ⚙️ **Security misconfigurations**
- 🚨 **CVE findings**
- 📁 **LFI vulnerabilities**

## 🛠️ Tools Used

<div align="center">
  
</div>

BugBusterPro automates the installation and usage of the following tools:

<div class="tools-grid">

[![subfinder](https://img.shields.io/badge/subfinder-Subdomain%20Discovery-blue)](https://github.com/projectdiscovery/subfinder)
[![httpx](https://img.shields.io/badge/httpx-HTTP%20Toolkit-green)](https://github.com/projectdiscovery/httpx)
[![katana](https://img.shields.io/badge/katana-Crawler-red)](https://github.com/projectdiscovery/katana)
[![waybackurls](https://img.shields.io/badge/waybackurls-Archive%20URLs-yellow)](https://github.com/tomnomnom/waybackurls)
[![otxurls](https://img.shields.io/badge/otxurls-OTX%20URLs-orange)](https://github.com/lc/otxurls)
[![feroxbuster](https://img.shields.io/badge/feroxbuster-Dir%20Bruteforce-purple)](https://github.com/epi052/feroxbuster)
[![nuclei](https://img.shields.io/badge/nuclei-Vuln%20Scanner-brightgreen)](https://github.com/projectdiscovery/nuclei)
[![subzy](https://img.shields.io/badge/subzy-Subdomain%20Takeover-blue)](https://github.com/lukasikic/subzy)
[![qsreplace](https://img.shields.io/badge/qsreplace-Query%20Replace-gray)](https://github.com/tomnomnom/qsreplace)
[![gf](https://img.shields.io/badge/gf-Pattern%20Matching-lightblue)](https://github.com/tomnomnom/gf)
[![bxss](https://img.shields.io/badge/bxss-Blind%20XSS-red)](https://github.com/ethicalhackingplayground/bxss)
[![Corsy](https://img.shields.io/badge/Corsy-CORS%20Testing-green)](https://github.com/s0md3v/Corsy)

</div>

## 🤝 Contributing

Contributions are welcome! Feel free to submit a Pull Request.

<div align="center">
  
</div>

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚠️ Disclaimer

This tool is intended for security professionals and bug bounty hunters to use on authorized targets only. The author is not responsible for any misuse or damage caused by this program. Always ensure you have explicit permission to test the target systems.

## 👤 Author


  
[![GitHub](https://img.shields.io/badge/GitHub-Harry7U-181717?style=for-the-badge&logo=github)](https://github.com/Harry7U)
  



## 🌟 Acknowledgements

- All the amazing open-source security tools this project depends on
- The bug bounty community for continuous inspiration and knowledge sharing

---

<div align="center">
  
Made with ❤️ for the bug bounty community
  
<sub>BugBusterPro © 2023-2025</sub>
  
</div>
