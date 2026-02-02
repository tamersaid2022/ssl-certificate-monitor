<div align="center">

# 🔒 SSL/TLS Certificate Monitor

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![SSL/TLS](https://img.shields.io/badge/SSL%2FTLS-Certificate_Analysis-4CAF50?style=for-the-badge&logo=letsencrypt&logoColor=white)](https://en.wikipedia.org/wiki/Transport_Layer_Security)
[![Flask](https://img.shields.io/badge/Flask-Dashboard-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Automated SSL/TLS certificate monitoring, expiration alerting, chain validation, and SSL inspection analysis for enterprise networks**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Dashboard](#-dashboard) • [API Reference](#-api-reference)

---

<img src="https://img.shields.io/badge/Certificates_Monitored-Unlimited-blue?style=for-the-badge" alt="Certs"/>
&nbsp;
<img src="https://img.shields.io/badge/Status-Production_Ready-success?style=for-the-badge" alt="Status"/>

</div>

## 🎯 Overview

The **SSL/TLS Certificate Monitor** provides enterprise-grade certificate lifecycle management and monitoring. It automatically discovers certificates across your infrastructure, validates certificate chains, detects SSL inspection issues (proxy/firewall re-signing), and alerts before expiration — preventing costly outages caused by expired certificates.

### Why This Tool?

| Problem | Solution |
|---------|----------|
| 🔴 Unexpected certificate expirations | Automated expiry tracking with 90/60/30/7 day alerts |
| 🔴 Broken certificate chains | Real-time chain validation and trust verification |
| 🔴 SSL inspection conflicts | Detect dual-inspection issues (Palo Alto + Zscaler) |
| 🔴 Wildcard cert sprawl | Centralized inventory of all certificates |
| 🔴 Compliance gaps | PCI-DSS / NIST TLS compliance checking |
| 🔴 Manual certificate tracking | Automated discovery across hosts and subnets |

---

## ⚡ Features

```
┌─────────────────────────────────────────────────────────────────┐
│                    CORE CAPABILITIES                            │
├─────────────────────────────────────────────────────────────────┤
│  🔍 DISCOVERY          │  📊 MONITORING        │  🔔 ALERTING   │
│  ────────────────────  │  ────────────────────  │  ───────────  │
│  • Single host scan    │  • Expiry tracking     │  • Email      │
│  • Subnet sweep        │  • Chain validation    │  • Slack      │
│  • Port scanning       │  • Protocol versions   │  • Teams      │
│  • Bulk CSV import     │  • Cipher analysis     │  • PagerDuty  │
│  • Auto-discovery      │  • Vulnerability check │  • Webhook    │
├─────────────────────────────────────────────────────────────────┤
│  🛡️ SECURITY ANALYSIS   │  📋 COMPLIANCE        │  🖥️ DASHBOARD │
│  ────────────────────  │  ────────────────────  │  ───────────  │
│  • Weak ciphers        │  • PCI-DSS checks     │  • Web UI     │
│  • Protocol downgrade  │  • NIST 800-52 Rev2   │  • REST API   │
│  • Key strength        │  • Certificate policy  │  • Real-time  │
│  • HSTS detection      │  • Audit reports       │  • Export     │
│  • SSL inspection      │  • Remediation guide   │  • History    │
│  • Proxy re-signing    │  • Scheduled scans     │  • Filters    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ SSL Inspection Analysis

One of the unique features of this tool is **SSL inspection conflict detection** — identifying when traffic passes through multiple SSL decryption points (e.g., Palo Alto firewall + Zscaler proxy), which can cause session failures and certificate trust issues.

### What It Detects

```
┌─────────────────────────────────────────────────────────────────┐
│                SSL INSPECTION ANALYSIS                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  CLIENT ──► FIREWALL (SSL Decrypt) ──► PROXY (SSL Inspect)     │
│                  │                          │                   │
│            Re-signed cert #1         Re-signed cert #2          │
│                                                                 │
│  DETECTS:                                                       │
│  ⚠️ Dual SSL inspection (firewall + proxy)                      │
│  ⚠️ Certificate re-signing by security appliances               │
│  ⚠️ Issuer mismatch (original vs intercepted)                   │
│  ⚠️ Trust chain broken by inspection                            │
│  ⚠️ Certificate pinning violations                              │
│  ⚠️ HSTS conflicts with inspection                              │
│                                                                 │
│  KNOWN INSPECTION ISSUERS:                                      │
│  • Palo Alto Networks     • Zscaler                             │
│  • Fortinet               • Blue Coat / Symantec               │
│  • Check Point            • Cisco Umbrella                      │
│  • Sophos                 • Barracuda                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/tamersaid2022/ssl-certificate-monitor.git
cd ssl-certificate-monitor

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### Requirements

```txt
cryptography>=41.0.0
pyOpenSSL>=23.0.0
flask>=3.0.0
requests>=2.31.0
pyyaml>=6.0
python-dotenv>=1.0.0
rich>=13.0.0
pandas>=2.0.0
apscheduler>=3.10.0
jinja2>=3.1.0
python-dateutil>=2.8.0
```

---

## 🚀 Usage

### Quick Start

```python
from ssl_monitor import SSLMonitor

# Initialize monitor
monitor = SSLMonitor()

# Check single host
cert = monitor.check_host("google.com", port=443)
print(f"Issuer: {cert.issuer}")
print(f"Expires: {cert.not_after}")
print(f"Days left: {cert.days_remaining}")
print(f"SSL Inspected: {cert.is_intercepted}")

# Scan multiple hosts
hosts = ["google.com", "github.com", "amazon.com", "cloudflare.com"]
results = monitor.scan_hosts(hosts)

# Export report
monitor.export_csv("certificates.csv")
monitor.export_html("certificate_report.html")
```

### Command Line Interface

```bash
# Check single host
python ssl_monitor.py check --host google.com

# Check host on custom port
python ssl_monitor.py check --host mail.company.com --port 587

# Scan multiple hosts from file
python ssl_monitor.py scan --file hosts.txt

# Scan subnet for SSL services
python ssl_monitor.py discover --network 192.168.1.0/24

# Check for expiring certificates (within 30 days)
python ssl_monitor.py expiring --days 30 --file hosts.txt

# Run compliance check
python ssl_monitor.py compliance --host company.com --standard pci-dss

# Detect SSL inspection
python ssl_monitor.py inspect --host internal-app.company.com

# Generate full report
python ssl_monitor.py report --file hosts.txt --output report.html

# Start web dashboard
python ssl_monitor.py dashboard --port 5000

# Schedule monitoring (check every 6 hours)
python ssl_monitor.py monitor --file hosts.txt --interval 6h --notify slack
```

---

## 📋 Configuration

### config.yaml

```yaml
# config.yaml
---
scanning:
  timeout: 10
  retries: 2
  threads: 20
  ports: [443, 8443, 636, 993, 995, 587, 465]
  
thresholds:
  critical: 7      # days before expiry
  warning: 30
  notice: 60
  info: 90
  
compliance:
  min_protocol: "TLSv1.2"
  min_key_size: 2048
  prohibited_ciphers:
    - RC4
    - DES
    - 3DES
    - MD5
    - NULL
    - EXPORT
  required_extensions:
    - subjectAltName
    - basicConstraints
    
ssl_inspection:
  known_issuers:
    - "Palo Alto Networks"
    - "Zscaler"
    - "Fortinet"
    - "Blue Coat"
    - "Symantec"
    - "Check Point"
    - "Cisco Umbrella"
    - "Sophos"
    - "Barracuda"
    - "Untangle"
    
alerting:
  email:
    enabled: true
    smtp_server: smtp.company.com
    recipients:
      - netops@company.com
      - security@company.com
  slack:
    enabled: true
    webhook_url: "${SLACK_WEBHOOK}"
    channel: "#certificate-alerts"
    
dashboard:
  host: 0.0.0.0
  port: 5000
  secret_key: "${FLASK_SECRET_KEY}"
```

### hosts.txt (One per line)

```
# Internal Services
mail.company.com:443
vpn.company.com:443
portal.company.com:8443
ldap.company.com:636

# External Services
google.com
github.com
aws.amazon.com
login.microsoftonline.com
```

---

## 📊 Sample Outputs

### Single Host Check

```
╔══════════════════════════════════════════════════════════════════╗
║              SSL/TLS CERTIFICATE REPORT                          ║
╠══════════════════════════════════════════════════════════════════╣
║  Host:           github.com:443                                  ║
║  Status:         ✅ VALID                                        ║
╠══════════════════════════════════════════════════════════════════╣
║  CERTIFICATE DETAILS                                             ║
║  ├─ Subject:     CN=github.com                                   ║
║  ├─ Issuer:      CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1 ║
║  ├─ Serial:      0E:8B:...                                       ║
║  ├─ Valid From:  2024-03-07                                      ║
║  ├─ Valid Until: 2025-03-07                                      ║
║  ├─ Days Left:   247 days ✅                                     ║
║  ├─ Key Type:    RSA 2048-bit                                    ║
║  └─ SANs:        github.com, www.github.com                     ║
╠══════════════════════════════════════════════════════════════════╣
║  TLS CONFIGURATION                                               ║
║  ├─ Protocol:    TLSv1.3 ✅                                      ║
║  ├─ Cipher:      TLS_AES_128_GCM_SHA256 ✅                      ║
║  ├─ HSTS:        Enabled (max-age=31536000) ✅                   ║
║  └─ OCSP:        Stapling enabled ✅                             ║
╠══════════════════════════════════════════════════════════════════╣
║  CHAIN VALIDATION                                                ║
║  ├─ [0] CN=github.com (Leaf)                                    ║
║  ├─ [1] CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1          ║
║  └─ [2] CN=DigiCert Global Root G2 (Root) ✅                    ║
╠══════════════════════════════════════════════════════════════════╣
║  SSL INSPECTION:  ✅ NOT DETECTED                                ║
║  COMPLIANCE:      ✅ PCI-DSS COMPLIANT                           ║
╚══════════════════════════════════════════════════════════════════╝
```

### SSL Inspection Detected

```
╔══════════════════════════════════════════════════════════════════╗
║              ⚠️ SSL INSPECTION DETECTED                          ║
╠══════════════════════════════════════════════════════════════════╣
║  Host:           internal-app.company.com:443                    ║
║  Original Issuer: DigiCert SHA2 Extended Validation Server CA   ║
║  Current Issuer:  Palo Alto Networks Decryption CA               ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  ⚠️  FINDINGS:                                                   ║
║  ├─ Certificate re-signed by: Palo Alto Networks                ║
║  ├─ Inspection type: Forward Proxy SSL Decryption               ║
║  ├─ Original cert hidden behind inspection                      ║
║  └─ Potential dual-inspection if Zscaler also active            ║
║                                                                  ║
║  💡 RECOMMENDATIONS:                                             ║
║  ├─ Verify decryption policy is intentional for this host       ║
║  ├─ Check for certificate pinning issues in client apps         ║
║  ├─ Ensure no dual SSL inspection (firewall + proxy)            ║
║  └─ Add to decryption bypass if causing connectivity issues     ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

### Expiration Summary

```
╔══════════════════════════════════════════════════════════════════╗
║              CERTIFICATE EXPIRATION REPORT                       ║
╠══════════════════════════════════════════════════════════════════╣
║  Total Monitored: 150 certificates                               ║
║  Scan Date:       2024-01-15 14:30:00                            ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  🔴 EXPIRED (2)                                                  ║
║  ├─ legacy-app.company.com    Expired 5 days ago                ║
║  └─ test.company.com          Expired 12 days ago               ║
║                                                                  ║
║  🔴 CRITICAL - Within 7 days (3)                                 ║
║  ├─ mail.company.com          Expires in 3 days                 ║
║  ├─ vpn.company.com           Expires in 5 days                 ║
║  └─ portal.company.com        Expires in 6 days                 ║
║                                                                  ║
║  🟠 WARNING - Within 30 days (8)                                 ║
║  ├─ api.company.com           Expires in 15 days                ║
║  ├─ wiki.company.com          Expires in 22 days                ║
║  └─ ... (6 more)                                                 ║
║                                                                  ║
║  🟡 NOTICE - Within 60 days (12)                                 ║
║  🟢 HEALTHY - Beyond 60 days (125)                               ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 🖥️ Dashboard

### Web Dashboard Overview

```
╔══════════════════════════════════════════════════════════════════════╗
║  🔒 SSL/TLS Certificate Monitor                     🟢 Monitoring    ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ ║
║  │   MONITORED  │  │   EXPIRING   │  │  INSPECTED   │  │  ISSUES  │ ║
║  │     150      │  │      13      │  │      34      │  │    5     │ ║
║  │  certificates│  │  within 30d  │  │  SSL decrypt │  │  alerts  │ ║
║  └──────────────┘  └──────────────┘  └──────────────┘  └──────────┘ ║
║                                                                      ║
║  CERTIFICATE HEALTH                    EXPIRY TIMELINE               ║
║  ─────────────────────────────────    ─────────────────────────────  ║
║  🟢 Healthy:    125 (83%)             │▓▓▓▓▓│ 7d:  3                ║
║  🟡 Notice:      12 (8%)              │▓▓▓▓▓▓▓▓│ 30d:  8           ║
║  🟠 Warning:      8 (5%)              │▓▓▓▓▓▓▓▓▓▓▓▓│ 60d: 12       ║
║  🔴 Critical:     3 (2%)              │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ 90d+: 125║
║  ⚫ Expired:      2 (1%)                                             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 🔌 API Reference

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/certificates` | GET | All monitored certificates |
| `/api/certificates/<host>` | GET | Certificate details for host |
| `/api/check` | POST | Check new host certificate |
| `/api/expiring` | GET | Certificates expiring soon |
| `/api/expiring?days=30` | GET | Expiring within N days |
| `/api/inspected` | GET | SSL-inspected certificates |
| `/api/compliance/<host>` | GET | Compliance report for host |
| `/api/scan` | POST | Trigger subnet scan |
| `/api/health` | GET | Monitor health summary |
| `/api/export` | GET | Export all data (CSV/JSON) |

### Example API Response

```json
// GET /api/certificates/github.com
{
  "host": "github.com",
  "port": 443,
  "status": "valid",
  "subject": "CN=github.com",
  "issuer": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
  "not_before": "2024-03-07T00:00:00Z",
  "not_after": "2025-03-07T23:59:59Z",
  "days_remaining": 247,
  "key_type": "RSA",
  "key_size": 2048,
  "protocol": "TLSv1.3",
  "cipher": "TLS_AES_128_GCM_SHA256",
  "san": ["github.com", "www.github.com"],
  "chain_valid": true,
  "chain_length": 3,
  "is_intercepted": false,
  "intercepted_by": null,
  "compliance": {
    "pci_dss": true,
    "nist": true
  },
  "last_checked": "2024-01-15T14:30:00Z"
}
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         BROWSER                                 │
│                    (Dashboard UI)                               │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTPS
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FLASK APPLICATION                             │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌────────────┐  │
│  │  Routes  │   │  REST    │   │ Scheduler│   │ WebSocket  │  │
│  │          │   │  API     │   │  (APS)   │   │            │  │
│  └──────────┘   └──────────┘   └──────────┘   └────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   CORE ENGINE                             │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │  │
│  │  │Discovery │  │Validator │  │Inspector │  │ Alerter  │ │  │
│  │  │          │  │          │  │          │  │          │ │  │
│  │  │• Subnet  │  │• Chain   │  │• Proxy   │  │• Email   │ │  │
│  │  │• Port    │  │• Expiry  │  │• Firewall│  │• Slack   │ │  │
│  │  │• Import  │  │• Cipher  │  │• Re-sign │  │• Webhook │ │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────────┘
                         │ TLS Connections
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   TARGET HOSTS                                  │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐          │
│  │ Web     │  │ Mail    │  │ VPN     │  │ API     │          │
│  │ Servers │  │ Servers │  │ Gateways│  │ Servers │          │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
ssl-certificate-monitor/
├── ssl_monitor.py           # Main application (single file)
├── config.yaml              # Configuration
├── hosts.txt                # Hosts to monitor
├── requirements.txt         # Dependencies
├── templates/
│   ├── dashboard.html       # Web dashboard
│   └── report.html.j2       # Report template
├── reports/
│   └── cert_report_YYYYMMDD.html
├── CONTRIBUTING.md
└── LICENSE
```

---

## 🔐 Security Considerations

| Concern | Implementation |
|---------|----------------|
| **Credential Storage** | Environment variables for all secrets |
| **Network Impact** | Rate limiting, configurable thread count |
| **Data Privacy** | Certificate data stored locally only |
| **Access Control** | Dashboard authentication support |
| **Audit Trail** | Full logging of all scan operations |
| **SNMP/SSH-free** | Only requires outbound TLS connections |

---

## 📈 Use Cases

| Scenario | How This Tool Helps |
|----------|---------------------|
| **Pre-renewal planning** | 90-day advance warning of expirations |
| **Outage prevention** | Automated alerts before certificates expire |
| **SSL troubleshooting** | Detect proxy/firewall SSL inspection conflicts |
| **Compliance auditing** | PCI-DSS and NIST TLS compliance reports |
| **Security assessment** | Identify weak ciphers, protocols, and key sizes |
| **Certificate inventory** | Centralized view of all certificates |
| **Incident response** | Quick chain validation during outages |

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### 👨‍💻 Author

**Tamer Khalifa** - *Network Automation Engineer*

[![CCIE](https://img.shields.io/badge/CCIE-68867-1BA0D7?style=flat-square&logo=cisco&logoColor=white)](https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/expert.html)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/tamerkhalifa2022)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat-square&logo=github)](https://github.com/tamersaid2022)

---

⭐ **Star this repo if you find it useful!** ⭐

</div>
