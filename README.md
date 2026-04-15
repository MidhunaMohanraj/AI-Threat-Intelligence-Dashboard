# 🛡️ AI Threat Intelligence Dashboard

<div align="center">

![Banner](https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=2,4,10&height=200&section=header&text=AI%20Threat%20Intel&fontSize=52&fontColor=fff&animation=twinkling&fontAlignY=35&desc=Live%20CVEs%20%E2%80%A2%20MITRE%20ATT%26CK%20%E2%80%A2%20IOC%20Detection%20%E2%80%A2%20AI%20Analysis%20%E2%80%A2%20Executive%20Briefing&descAlignY=55&descSize=14)

<p>
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Streamlit-1.35-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white"/>
  <img src="https://img.shields.io/badge/Gemini%201.5%20Flash-Free%20API-4285F4?style=for-the-badge&logo=google&logoColor=white"/>
  <img src="https://img.shields.io/badge/NIST%20NVD-Live%20CVEs-dc2626?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-7c3aed?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge"/>
</p>

<p>
  <b>Pull live threat intelligence from NIST NVD, CISA, and top security news feeds → Gemini AI maps each threat to MITRE ATT&CK tactics, extracts IOCs, scores urgency, and generates an executive briefing.</b>
</p>

</div>

---

## 🌟 What This Does

```
LIVE FEEDS                    AI ANALYSIS               DASHBOARD
─────────────                 ───────────               ─────────
NIST NVD CVEs    ──►          Severity scoring  ──►    Threat feed
CISA Advisories  ──►  Gemini  MITRE ATT&CK map  ──►    Deep analysis
BleepingComputer ──►   1.5    IOC extraction    ──►    Analytics
Krebs on Sec     ──►  Flash   Impact assessment ──►    CVE tracker
SANS ISC         ──►          Recommendations   ──►    Exec briefing
Dark Reading     ──►          Threat actor ID   ──►    JSON export
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔓 **Live CVE Feed** | Real-time vulnerabilities from NIST NVD REST API v2 with CVSS scores |
| 📡 **8 Security Feeds** | BleepingComputer, Krebs, SANS ISC, Dark Reading, CISA, Threatpost, Schneier |
| 🤖 **AI Threat Analysis** | Per-threat: summary, impact, affected systems, MITRE tactics, IOCs, recommendations |
| 🎯 **MITRE ATT&CK Mapping** | Maps each threat to relevant ATT&CK tactics automatically |
| 🔍 **IOC Extraction** | Identifies indicators of compromise from threat descriptions |
| ⚡ **Urgency Scoring** | Immediate / This-Week / Monitor / Informational |
| 👤 **Threat Actor ID** | Identifies known APT groups and threat actors |
| 📋 **Executive Briefing** | C-suite ready threat summary with recommended actions |
| 📊 **Analytics** | Severity charts, category breakdown, MITRE coverage heatmap |
| 🔓 **CVE Tracker** | Sortable table of all CVEs with CVSS, affected products, dates |
| 💾 **JSON Export** | Full intelligence report download |

---

## 🚀 Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/ai-threat-intel.git
cd ai-threat-intel
pip install -r requirements.txt
streamlit run app.py
```

---

## 🧠 Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Data Collection Layer                                   │
│  ├── NIST NVD API v2 (CVE-2024-*, CVSS scores)          │
│  └── feedparser → 8 RSS/Atom security feeds             │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│  Processing Layer                                        │
│  ├── Severity classification (CVSS + keyword heuristic) │
│  ├── Category detection (malware/phishing/vuln/apt...)  │
│  ├── CVE ID extraction                                   │
│  └── Deduplication                                       │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│  AI Analysis (Gemini 1.5 Flash, temp=0.1)               │
│  Per threat:                                             │
│  ├── Plain English summary                               │
│  ├── Business impact assessment                          │
│  ├── Affected systems identification                     │
│  ├── MITRE ATT&CK tactic mapping                        │
│  ├── IOC extraction                                      │
│  ├── Specific defensive recommendations                  │
│  ├── Threat actor attribution                            │
│  └── Urgency classification                              │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│  Executive Briefing (separate Gemini call)              │
│  ├── Threat level: CRITICAL / HIGH / ELEVATED           │
│  ├── C-suite executive summary                           │
│  ├── Top 5 threats of the day                           │
│  ├── Trending TTPs                                       │
│  └── Recommended immediate actions                       │
└──────────────────────────────────────────────────────────┘
```

---

## 📡 Data Sources

| Source | Type | Free? |
|---|---|---|
| NIST NVD API v2 | CVE vulnerabilities | ✅ No key needed |
| CISA Advisories | Government alerts | ✅ RSS |
| BleepingComputer | Security news | ✅ RSS |
| Krebs on Security | Investigative security | ✅ RSS |
| SANS ISC | Daily threat advisories | ✅ RSS |
| Dark Reading | Industry news | ✅ RSS |
| Threatpost | Breaking security news | ✅ RSS |
| Schneier on Security | Expert analysis | ✅ RSS |

---

## 📁 Project Structure

```
ai-threat-intel/
├── app.py                   # 🖥️ Streamlit dashboard — 5 tabs
├── src/
│   └── threat_engine.py     # 🧠 Feed fetcher + AI analysis engine
├── requirements.txt         # 📦 6 dependencies
├── README.md
└── LICENSE
```

---

## 🗺️ Roadmap

- [ ] VirusTotal API integration for hash/domain lookup
- [ ] Shodan integration for exposed service detection
- [ ] Slack/email alerting for critical threats
- [ ] Historical trend tracking (SQLite)
- [ ] Custom IOC watchlist with alerts
- [ ] STIX/TAXII format export

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

**⭐ Star this repo if you find it useful!**

*Stay informed. Patch fast. Defend better.*

![Footer](https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=2,4,10&height=100&section=footer)

</div>
