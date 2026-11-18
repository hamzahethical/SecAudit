<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<h1 align="center">🛡️ SecAudit</h1>
<h3 align="center">Web Security Headers & SSL/TLS Auditor</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-3572A5?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Security-Headers%20Audit-red?style=for-the-badge&logo=shield&logoColor=white" />
  <img src="https://img.shields.io/badge/SSL-TLS%20Check-blue?style=for-the-badge&logo=letsencrypt&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=18&pause=1000&color=00FF66&center=true&vCenter=true&width=600&lines=Scan+any+website+for+security+misconfigs;Check+9+critical+security+headers;Analyze+SSL/TLS+certificates;Generate+a+security+score+%26+grade" alt="Typing SVG" />
</p>

---

## 🔍 What is SecAudit?

**SecAudit** is a command-line Python tool that audits any website for:
- **9 Critical HTTP Security Headers** (HSTS, CSP, X-Frame-Options, etc.)
- **Information-leaking headers** that expose server fingerprint (Server, X-Powered-By)
- **SSL/TLS Certificate** validity, expiry, and self-signed detection
- Outputs a beautiful **color-coded terminal report** with a **Security Score (0–100) & Grade (A+ to F)**
- Optionally **saves a JSON report** for documentation

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/hamzahethical/SecAudit.git
cd SecAudit

# Install dependencies (only 1 optional dependency for colored output)
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
# Basic scan
python secaudit.py -u example.com

# Scan with explicit HTTPS
python secaudit.py -u https://google.com

# Output raw JSON to terminal
python secaudit.py -u example.com --json

# Save report to file
python secaudit.py -u example.com -o report.json
```

---

## 📊 Sample Output

```
╭────────────────────────────────────────╮
│  Overall Result                        │
│  Security Score: 45/100   Grade: D     │
╰────────────────────────────────────────╯

✅ Present Security Headers
┌─────────────────────────┬──────────────────────────┐
│ X-Content-Type-Options  │ nosniff                  │
│ X-Frame-Options         │ SAMEORIGIN               │
└─────────────────────────┴──────────────────────────┘

❌ Missing Security Headers
┌──────────────────────────────┬──────────┬──────────────────────────────────┐
│ Header                       │ Severity │ Description                      │
├──────────────────────────────┼──────────┼──────────────────────────────────┤
│ Strict-Transport-Security    │  HIGH    │ Forces HTTPS connections (HSTS)  │
│ Content-Security-Policy      │  HIGH    │ Prevents XSS attacks             │
│ Permissions-Policy           │  LOW     │ Controls browser features        │
└──────────────────────────────┴──────────┴──────────────────────────────────┘

⚠️  Information-Leaking Headers
┌───────────┬───────────────────────────────┐
│ Server    │ Apache/2.4.41 (Ubuntu)        │
│ X-Powered │ PHP/7.4.3                     │
└───────────┴───────────────────────────────┘

🔒 SSL / TLS Certificate
┌──────────┬────────────────────────────────┐
│ Status   │ ✓ Valid                        │
│ Protocol │ TLSv1.3                        │
│ Issuer   │ Let's Encrypt                  │
│ Expires  │ 2025-03-15                     │
│ Days Left│ 87                             │
└──────────┴────────────────────────────────┘
```

---

## 📋 Headers Checked

| Header | Severity | Purpose |
| :----- | :------: | :------ |
| `Strict-Transport-Security` | 🔴 HIGH | Forces HTTPS — prevents protocol downgrade attacks |
| `Content-Security-Policy` | 🔴 HIGH | Restricts resource loading — prevents XSS |
| `X-Frame-Options` | 🟡 MEDIUM | Prevents Clickjacking |
| `X-Content-Type-Options` | 🟡 MEDIUM | Prevents MIME-type sniffing |
| `Cross-Origin-Opener-Policy` | 🟡 MEDIUM | Prevents cross-origin window abuse |
| `Cross-Origin-Resource-Policy` | 🟡 MEDIUM | Prevents cross-origin resource leakage |
| `Referrer-Policy` | 🔵 LOW | Controls referrer data leakage |
| `Permissions-Policy` | 🔵 LOW | Controls browser feature access |
| `X-XSS-Protection` | 🔵 LOW | Legacy XSS filter |

---

## ⚙️ Requirements

- Python 3.7+
- `rich` library (optional — for colorful terminal output)

```
rich>=10.0.0
```

---

## ⚠️ Disclaimer

**SecAudit** is built strictly for **educational purposes** and **authorized security auditing only**. Never scan a website without explicit written permission from the owner.

---

## 👨‍💻 Author

**Md Hamzah** | [@hamzahethical](https://github.com/hamzahethical)  
Cybersecurity Specialist | Ethical Hacker | Security Researcher  
📍 Kolkata, India 🇮🇳
