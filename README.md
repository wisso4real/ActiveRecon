# ActiveRecon v1.0

**Complete Active Reconnaissance Tool for Penetration Testing**

⚠️ **Note**: This tool is currently in active development. Features and functionality may change.

## Overview

ActiveRecon is a comprehensive network reconnaissance framework designed for penetration testers and security professionals. Built entirely with Bash scripting, it adheres to established methodologies from OWASP, NIST, and PTES, automating the entire active reconnaissance process through well-structured and systematic phases.
## Features

- **8-Phase Methodology**: Target validation → Network discovery → Port scanning → Service enumeration → Protocol analysis → Infrastructure mapping → Vulnerability assessment → Evidence processing
- **Flexible Scanning Modes**: Quick scan, full scan, stealth mode
- **Professional Reporting**: Executive summaries, technical reports, attack surface analysis
- **Service Enumeration**: Web, database, SMB, SSH, FTP, DNS, SNMP services
- **Automated Documentation**: Evidence collection and remediation tracking
- **Quality Assurance**: Built-in validation and verification checks

## Installation

```bash
git clone https://github.com/wisso4real/ActiveRecon.git
cd ActiveRecon
chmod +x ActiveRecon.sh
```

## Dependencies

- nmap
- masscan
- netcat (nc)
- dig
- whois
- curl

## Usage

### Basic Scan
```bash
./Activerecon.sh 192.168.1.0/24
```

### Quick Assessment
```bash
./ActiveRecon.sh -q -o quick_scan 10.0.0.0/16
```

### Full Stealth Scan
```bash
sudo ./ActiveRecon.sh -f -s -t 25 target.com
```

### Advanced Options
```bash
./ActiveRecon.sh [OPTIONS] TARGET_RANGE

Options:
  -o, --output DIR     Output directory
  -t, --threads NUM    Number of threads (default: 50)
  -T, --timing NUM     Timing template 0-5 (default: 4)
  -q, --quick          Quick scan (top 1000 ports)
  -f, --full           Full scan (all 65535 ports)
  -s, --stealth        Stealth mode
  -v, --verbose        Verbose output
  -x, --exploit        Enable auto-exploitation
  -h, --help           Show help
```

## Output Structure

```
activerecon_TIMESTAMP/
├── discovery/          # Network discovery results
├── scanning/           # Port scanning data
├── enumeration/        # Service enumeration
├── vulnerabilities/    # Security assessment
├── infrastructure/     # Network mapping
├── evidence/          # Consolidated evidence
├── reports/           # Professional reports
└── activerecon.log    # Complete audit trail
```

## Reports Generated

- **Executive Summary**: Management-ready overview
- **Technical Report**: Detailed technical findings
- **Attack Surface Report**: Complete attack surface analysis
- **Service Inventory**: Comprehensive service catalog
- **Remediation Tracking**: Issue tracking template

## Development Status

🚧 **Active Development**: This tool is currently under development. Contributions, bug reports, and feature requests are welcome.

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## Feedback

Suggestions and feedback are welcomed at: **reaper.gitbook@gmail.com**

## Legal Disclaimer

This tool is intended for authorized security testing only. Users are responsible for complying with applicable laws and regulations. The author assumes no liability for misuse of this tool.

---

**⭐ Star this repo if you find it useful!**
