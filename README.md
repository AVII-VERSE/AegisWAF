# 🛡️ AegisWAF - Next-Gen AI Web Security Command Center

<p align="center">
  <img src="./output-screenshots/aegis-ss1.png" alt="AegisWAF Command Center Overview" width="850"/>
</p>

<p align="center">
  <a href="#features"><img src="https://img.shields.io/badge/Engine-Dual--Layer%20Hybrid-8b5cf6?style=for-the-badge" alt="Dual-Layer"></a>
  <a href="#features"><img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
  <a href="#features"><img src="https://img.shields.io/badge/Framework-Flask-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"></a>
  <a href="#features"><img src="https://img.shields.io/badge/ML%20Engine-Scikit--Learn-orange?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="Scikit-Learn"></a>
  <a href="#features"><img src="https://img.shields.io/badge/Database-SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite"></a>
</p>

> **AegisWAF** is a sleek, enterprise-grade Web Application Firewall (WAF) and real-time Security Command Center. It safeguards web applications against OWASP Top 10 security threats—such as SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), Path Traversal, SSRF, and JNDI exploits—by combining deterministic signature pattern matching with machine learning anomaly detection.

---

## 📸 Interface Preview

<p float="left" align="center">
  <img src="./output-screenshots/aegis-ss1.png" width="410" alt="Security Command Center Overview"/>
  <img src="./output-screenshots/aegis-ss2.png" width="410" alt="Live Payload Inspector & Risk Meter"/>
</p>

<p align="center">
  <img src="./output-screenshots/aegis-ss3.png" width="830" alt="SOC Dashboard & Threat Logs Table"/>
</p>

---

## ✨ Features

- **⚡ Layer-1 Signature Matching:** Instant sub-millisecond threat mitigation for SQLi, XSS, RCE, Path Traversal, and SSRF.
- **🤖 Layer-2 AI Anomaly Inspector:** 8-dimensional statistical feature vector (Shannon Entropy, length ratios, special char density) to flag zero-day exploits and obfuscated payloads.
- **💻 Futuristic Command Center UI:** Single-page interface featuring dark obsidian aesthetic, electric violet & cyan accents, risk meter gauge, and feature radar charts.
- **📊 SOC Telemetry & CSV Export:** Real-time threat distribution metrics, filterable log tables, and instant `.csv` log downloads.
- **🗄️ SQLite Database Persistence:** Automatic runtime logging of all incoming request vectors.

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the AegisWAF Command Center
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
