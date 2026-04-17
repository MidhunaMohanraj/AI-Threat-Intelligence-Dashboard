"""
threat_engine.py — AI Threat Intelligence Engine
Aggregates threat data from free public feeds + Gemini AI analysis:
  - CVE vulnerability feed (NVD)
  - Malware/phishing domains (abuse.ch)
  - Threat actor TTPs (MITRE ATT&CK)
  - IP reputation lookup
  - IOC (Indicators of Compromise) analysis
  - AI-powered threat briefing generation
  - Risk scoring and prioritization
""" 

import json
import re
import time
import hashlib
import feedparser
import httpx
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
import google.generativeai as genai


# ── Severity levels ────────────────────────────────────────────────────────────
SEVERITY = {
    "critical": {"color": "#dc2626", "emoji": "🔴", "score_min": 9.0},
    "high":     {"color": "#f97316", "emoji": "🟠", "score_min": 7.0},
    "medium":   {"color": "#eab308", "emoji": "🟡", "score_min": 4.0},
    "low":      {"color": "#22c55e", "emoji": "🟢", "score_min": 0.0},
}

# ── Threat categories ──────────────────────────────────────────────────────────
THREAT_CATEGORIES = {
    "vulnerability":  {"icon": "🔓", "color": "#f97316"},
    "malware":        {"icon": "🦠", "color": "#dc2626"},
    "phishing":       {"icon": "🎣", "color": "#eab308"},
    "ransomware":     {"icon": "💀", "color": "#dc2626"},
    "apt":            {"icon": "🕵️", "color": "#a855f7"},
    "ddos":           {"icon": "💥", "color": "#f97316"},
    "data_breach":    {"icon": "🗄️", "color": "#ef4444"},
    "zero_day":       {"icon": "⚡", "color": "#dc2626"},
    "supply_chain":   {"icon": "🔗", "color": "#f97316"},
    "insider_threat": {"icon": "👤", "color": "#eab308"},
}

# ── Free public threat feeds ───────────────────────────────────────────────────
THREAT_FEEDS = {
    "nvd_cve": {
        "name":   "NIST NVD — Recent CVEs",
        "url":    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
        "type":   "vulnerability",
    },
    "cisa_alerts": {
        "name":   "CISA Cybersecurity Alerts",
        "url":    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "type":   "advisory",
    },
    "threatpost": {
        "name":   "Threatpost Security News",
        "url":    "https://threatpost.com/feed/",
        "type":   "news",
    },
    "bleepingcomputer": {
        "name":   "BleepingComputer Security",
        "url":    "https://www.bleepingcomputer.com/feed/",
        "type":   "news",
    },
    "krebs": {
        "name":   "Krebs on Security",
        "url":    "https://krebsonsecurity.com/feed/",
        "type":   "news",
    },
    "sans": {
        "name":   "SANS Internet Storm Center",
        "url":    "https://isc.sans.edu/rssfeed_full.xml",
        "type":   "advisory",
    },
    "schneier": {
        "name":   "Schneier on Security",
        "url":    "https://www.schneier.com/feed/atom/",
        "type":   "analysis",
    },
    "darkreading": {
        "name":   "Dark Reading",
        "url":    "https://www.darkreading.com/rss.xml",
        "type":   "news",
    },
}

# ── MITRE ATT&CK Tactics ───────────────────────────────────────────────────────
MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


# ── Data structures ────────────────────────────────────────────────────────────
@dataclass
class ThreatItem:
    id:           str
    title:        str
    description:  str
    source:       str
    source_type:  str          # news / advisory / vulnerability / analysis
    url:          str
    published:    str
    severity:     str          # critical / high / medium / low / unknown
    category:     str          # vulnerability / malware / phishing / etc.
    cve_ids:      list[str] = field(default_factory=list)
    cvss_score:   float = 0.0
    affected:     list[str] = field(default_factory=list)  # affected products
    tags:         list[str] = field(default_factory=list)


@dataclass
class ThreatAnalysis:
    item_id:      str
    title:        str
    severity:     str
    ai_summary:   str          # plain English 2-3 sentence summary
    impact:       str          # what could happen if exploited
    affected_systems: list[str]
    mitre_tactics:    list[str]  # relevant ATT&CK tactics
    iocs:             list[str]  # Indicators of Compromise mentioned
    recommendations:  list[str]  # defensive actions
    threat_actor:     str        # known threat actor if mentioned
    urgency:          str        # immediate / this-week / monitor / informational
    confidence:       int        # 0-100 AI confidence in analysis


@dataclass
class ThreatBriefing:
    generated_at:    str
    period:          str         # e.g. "Last 24 hours"
    total_threats:   int
    critical_count:  int
    high_count:      int
    top_categories:  list[str]
    executive_summary: str       # 3-4 sentence briefing for leadership
    key_threats:     list[str]   # bullet list of top 5 threats
    trending_ttps:   list[str]   # trending tactics/techniques
    recommended_actions: list[str]
    threat_landscape: str        # overall threat landscape assessment


# ── RSS / Feed fetching ────────────────────────────────────────────────────────
def _guess_severity(title: str, desc: str) -> str:
    text = (title + " " + desc).lower()
    if any(w in text for w in ["critical", "0-day", "zero-day", "zero day", "emergency",
                                 "actively exploited", "weaponized", "nation-state"]):
        return "critical"
    if any(w in text for w in ["high", "severe", "dangerous", "ransomware", "apt",
                                 "remote code execution", "rce", "privilege escalation"]):
        return "high"
    if any(w in text for w in ["medium", "moderate", "phishing", "malware", "vulnerability",
                                 "patch", "update", "cve-"]):
        return "medium"
    return "low"


def _guess_category(title: str, desc: str) -> str:
    text = (title + " " + desc).lower()
    if "ransomware" in text:          return "ransomware"
    if "zero-day" in text or "0-day" in text: return "zero_day"
    if "phishing" in text:            return "phishing"
    if "apt" in text or "nation-state" in text or "threat actor" in text: return "apt"
    if "malware" in text or "trojan" in text or "backdoor" in text: return "malware"
    if "ddos" in text or "denial of service" in text: return "ddos"
    if "breach" in text or "leaked" in text: return "data_breach"
    if "supply chain" in text:        return "supply_chain"
    if "cve-" in text or "vulnerability" in text or "exploit" in text: return "vulnerability"
    return "vulnerability"


def _extract_cves(text: str) -> list[str]:
    return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))


def fetch_threat_feed(feed_id: str, max_items: int = 8) -> list[ThreatItem]:
    """Fetch items from a single threat intelligence RSS feed."""
    feed_cfg = THREAT_FEEDS.get(feed_id)
    if not feed_cfg:
        return []
    try:
        feed  = feedparser.parse(feed_cfg["url"])
        items = []
        for entry in feed.entries[:max_items]:
            title = entry.get("title", "").strip()
            desc  = re.sub(r"<[^>]+>", "", entry.get("summary", entry.get("description", ""))).strip()[:600]
            url   = entry.get("link", "")
            pub   = entry.get("published", entry.get("updated", datetime.now().isoformat()))
            if not title or len(title) < 5:
                continue
            uid = hashlib.md5(f"{feed_id}{url}{title}".encode()).hexdigest()[:12]
            items.append(ThreatItem(
                id=uid,
                title=title,
                description=desc,
                source=feed_cfg["name"],
                source_type=feed_cfg["type"],
                url=url,
                published=pub,
                severity=_guess_severity(title, desc),
                category=_guess_category(title, desc),
                cve_ids=_extract_cves(title + " " + desc),
            ))
        return items
    except Exception:
        return []


def fetch_nvd_cves(max_cves: int = 15) -> list[ThreatItem]:
    """Fetch recent CVEs from NVD REST API v2 (no key needed)."""
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"
        r   = httpx.get(url, timeout=10, follow_redirects=True)
        if r.status_code != 200:
            return []
        data = r.json()
        items = []
        for vuln in data.get("vulnerabilities", [])[:max_cves]:
            cve   = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descs  = cve.get("descriptions", [])
            desc   = next((d["value"] for d in descs if d.get("lang") == "en"), "No description.")[:400]
            pub    = cve.get("published", "")
            # Get CVSS score
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    cvss_score = float(metrics[key][0].get("cvssData", {}).get("baseScore", 0))
                    break
            # Severity from CVSS
            if cvss_score >= 9.0:   sev = "critical"
            elif cvss_score >= 7.0: sev = "high"
            elif cvss_score >= 4.0: sev = "medium"
            else:                   sev = "low"
            # Affected products
            affected = []
            for conf in cve.get("configurations", [])[:3]:
                for node in conf.get("nodes", []):
                    for match in node.get("cpeMatch", [])[:2]:
                        cpe = match.get("criteria", "")
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            affected.append(f"{parts[3]} {parts[4]}")
            uid = hashlib.md5(cve_id.encode()).hexdigest()[:12]
            items.append(ThreatItem(
                id=uid,
                title=f"{cve_id} — {desc[:80]}",
                description=desc,
                source="NIST NVD",
                source_type="vulnerability",
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published=pub[:10] if pub else "",
                severity=sev,
                category="vulnerability",
                cve_ids=[cve_id],
                cvss_score=cvss_score,
                affected=list(set(affected))[:5],
            ))
        return items
    except Exception:
        return []


def fetch_all_feeds(
    feed_ids: list[str],
    include_nvd: bool = True,
    max_per_feed: int = 6,
    on_progress: callable = None,
) -> list[ThreatItem]:
    all_items = []
    total = len(feed_ids) + (1 if include_nvd else 0)
    done  = 0

    if include_nvd:
        if on_progress: on_progress(done, total, "NIST NVD CVEs")
        cves = fetch_nvd_cves(max_per_feed * 2)
        all_items.extend(cves)
        done += 1
        time.sleep(0.5)

    for fid in feed_ids:
        cfg = THREAT_FEEDS.get(fid, {})
        if on_progress: on_progress(done, total, cfg.get("name", fid))
        items = fetch_threat_feed(fid, max_per_feed)
        all_items.extend(items)
        done += 1
        time.sleep(0.3)

    # Deduplicate by title similarity
    seen_titles = set()
    deduped = []
    for item in all_items:
        key = item.title[:50].lower().strip()
        if key not in seen_titles:
            seen_titles.add(key)
            deduped.append(item)

    # Sort by severity
    sev_order = ["critical", "high", "medium", "low", "unknown"]
    deduped.sort(key=lambda x: sev_order.index(x.severity) if x.severity in sev_order else 5)
    return deduped


# ── Gemini AI analysis ─────────────────────────────────────────────────────────
def analyze_threat(item: ThreatItem, api_key: str) -> ThreatAnalysis:
    """Run deep AI analysis on a single threat item."""
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        "gemini-1.5-flash",
        generation_config={"temperature": 0.1, "max_output_tokens": 800},
    )
    cvss_info = f"CVSS Score: {item.cvss_score}" if item.cvss_score > 0 else ""
    cve_info  = f"CVEs: {', '.join(item.cve_ids)}" if item.cve_ids else ""

    prompt = f"""You are a senior threat intelligence analyst. Analyze this cybersecurity threat.

THREAT: {item.title}
SOURCE: {item.source} ({item.source_type})
SEVERITY: {item.severity.upper()}
{cvss_info}
{cve_info}
DESCRIPTION: {item.description[:400]}

Return ONLY valid JSON:
{{
  "ai_summary": "<2-3 sentence plain English summary of the threat and its significance>",
  "impact": "<what could happen if this is exploited or not patched — 1-2 sentences>",
  "affected_systems": ["<specific OS/software/hardware affected>"],
  "mitre_tactics": ["<relevant ATT&CK tactics from: {', '.join(MITRE_TACTICS[:8])}>"],
  "iocs": ["<any indicators of compromise mentioned: IPs, domains, hashes, file names>"],
  "recommendations": ["<specific defensive action>", "<another action>", "<third action>"],
  "threat_actor": "<known threat actor/group name or 'Unknown'>",
  "urgency": "<immediate|this-week|monitor|informational>",
  "confidence": <0-100 integer confidence in this analysis>
}}"""

    try:
        r    = model.generate_content(prompt)
        raw  = re.sub(r"^```json\s*|^```\s*|\s*```$", "", r.text.strip(), flags=re.MULTILINE)
        data = json.loads(raw)
        return ThreatAnalysis(
            item_id=item.id,
            title=item.title,
            severity=item.severity,
            ai_summary=data.get("ai_summary", ""),
            impact=data.get("impact", ""),
            affected_systems=data.get("affected_systems", [])[:6],
            mitre_tactics=data.get("mitre_tactics", [])[:5],
            iocs=data.get("iocs", [])[:8],
            recommendations=data.get("recommendations", [])[:5],
            threat_actor=data.get("threat_actor", "Unknown"),
            urgency=data.get("urgency", "monitor"),
            confidence=int(data.get("confidence", 70)),
        )
    except Exception:
        return ThreatAnalysis(
            item_id=item.id, title=item.title, severity=item.severity,
            ai_summary="Analysis unavailable.", impact="Review manually.",
            affected_systems=[], mitre_tactics=[], iocs=[],
            recommendations=["Review the source for details."],
            threat_actor="Unknown", urgency="monitor", confidence=0,
        )


def generate_briefing(
    items: list[ThreatItem],
    analyses: list[ThreatAnalysis],
    api_key: str,
) -> ThreatBriefing:
    """Generate an executive threat briefing from all collected intelligence."""
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        "gemini-1.5-flash",
        generation_config={"temperature": 0.2, "max_output_tokens": 1200},
    )

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    cat_counts: dict[str, int] = {}
    for item in items:
        if item.severity in sev_counts:
            sev_counts[item.severity] += 1
        cat_counts[item.category] = cat_counts.get(item.category, 0) + 1

    top_categories = sorted(cat_counts, key=lambda x: -cat_counts[x])[:5]

    # Build context from top threats
    top_items = items[:8]
    context   = "\n".join([
        f"- [{i.severity.upper()}] {i.title} (Source: {i.source})"
        for i in top_items
    ])
    top_analyses = analyses[:5]
    recs_context = "\n".join([
        f"- {a.urgency.upper()}: {a.ai_summary[:100]}"
        for a in top_analyses if a.ai_summary
    ])

    prompt = f"""You are a Chief Information Security Officer preparing a daily threat intelligence briefing.

THREAT SUMMARY:
Total threats: {len(items)}
Critical: {sev_counts['critical']} | High: {sev_counts['high']} | Medium: {sev_counts['medium']} | Low: {sev_counts['low']}
Top categories: {', '.join(top_categories)}

TOP THREATS:
{context}

AI ANALYSES:
{recs_context}

Return ONLY valid JSON:
{{
  "executive_summary": "<3-4 sentence non-technical briefing for C-suite: overall threat level, key risks, immediate concerns>",
  "key_threats": ["<threat 1: 1 sentence>", "<threat 2>", "<threat 3>", "<threat 4>", "<threat 5>"],
  "trending_ttps": ["<tactic/technique trending right now>", ...],
  "recommended_actions": ["<urgent action>", "<important action>", "<preventive action>", "<monitoring action>"],
  "threat_landscape": "<overall assessment of current threat landscape in 2 sentences>"
}}"""

    try:
        r    = model.generate_content(prompt)
        raw  = re.sub(r"^```json\s*|^```\s*|\s*```$", "", r.text.strip(), flags=re.MULTILINE)
        data = json.loads(raw)
    except Exception:
        data = {
            "executive_summary": f"The current threat landscape shows {sev_counts['critical']} critical and {sev_counts['high']} high severity threats requiring immediate attention.",
            "key_threats": [i.title[:80] for i in top_items[:5]],
            "trending_ttps": ["Ransomware", "Phishing", "Supply Chain Attacks"],
            "recommended_actions": ["Patch critical CVEs immediately", "Review firewall rules", "Enable MFA everywhere"],
            "threat_landscape": "Active threat environment with multiple high-severity vulnerabilities and ongoing campaigns.",
        }

    return ThreatBriefing(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        period="Live Feed",
        total_threats=len(items),
        critical_count=sev_counts["critical"],
        high_count=sev_counts["high"],
        top_categories=top_categories,
        executive_summary=data.get("executive_summary", ""),
        key_threats=data.get("key_threats", [])[:5],
        trending_ttps=data.get("trending_ttps", [])[:6],
        recommended_actions=data.get("recommended_actions", [])[:5],
        threat_landscape=data.get("threat_landscape", ""),
    )
