"""
app.py — AI Threat Intelligence Dashboard
""" 
import sys, json 
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd    
from pathlib import Path
from dataclasses import asdict
from collections import Counter  
sys.path.insert(0, str(Path(__file__).parent / "src"))
from threat_engine import (
    THREAT_FEEDS, SEVERITY, THREAT_CATEGORIES, MITRE_TACTICS,
    fetch_all_feeds, analyze_threat, generate_briefing,
    ThreatItem, ThreatAnalysis, ThreatBriefing,
)
  
# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
  .main { background: #060709; }

  .hero {
    background: linear-gradient(135deg,#060709 0%,#080c0f 50%,#06090a 100%);
    border:1px solid #0f1e20; border-radius:16px;
    padding:32px 40px; text-align:center; margin-bottom:20px;
    position:relative; overflow:hidden;
  }
  .hero::before {
    content:"THREAT INTEL";
    position:absolute; font-size:100px; font-weight:900;
    color:rgba(239,68,68,0.04); top:50%; left:50%;
    transform:translate(-50%,-50%); white-space:nowrap;
    font-family:'JetBrains Mono',monospace; letter-spacing:4px;
  }
  .hero h1 { font-size:38px; font-weight:700; color:#fff; margin:0 0 6px; position:relative; }
  .hero p  { color:#475569; font-size:14px; margin:0; position:relative; }

  .threat-critical { background:#0f0203; border:1px solid #7f1d1d; border-left:4px solid #dc2626; border-radius:0 10px 10px 0; padding:14px 18px; margin:7px 0; }
  .threat-high     { background:#0f0600; border:1px solid #7c2d12; border-left:4px solid #f97316; border-radius:0 10px 10px 0; padding:14px 18px; margin:7px 0; }
  .threat-medium   { background:#0f0d00; border:1px solid #78350f; border-left:4px solid #eab308; border-radius:0 10px 10px 0; padding:14px 18px; margin:7px 0; }
  .threat-low      { background:#030f03; border:1px solid #14532d; border-left:4px solid #22c55e; border-radius:0 10px 10px 0; padding:14px 18px; margin:7px 0; }

  .threat-title { font-size:13px; font-weight:700; color:#e2e8f0; line-height:1.5; margin-bottom:4px; }
  .threat-desc  { font-size:12px; color:#64748b; line-height:1.6; margin-bottom:8px; }
  .threat-meta  { display:flex; gap:10px; flex-wrap:wrap; font-size:11px; color:#475569; }

  .sev-pill { display:inline-block; padding:2px 8px; border-radius:20px; font-size:10px; font-weight:700; letter-spacing:1px; }
  .tag      { display:inline-block; background:#0f1320; border:1px solid #1e2a40; color:#60a5fa; padding:2px 8px; border-radius:4px; font-size:10px; margin:2px; }
  .ioc      { display:inline-block; background:#0f0a00; border:1px solid #78350f; color:#fcd34d; padding:2px 8px; border-radius:4px; font-size:10px; font-family:'JetBrains Mono',monospace; margin:2px; }
  .mitre    { display:inline-block; background:#0a050f; border:1px solid #4c1d95; color:#c4b5fd; padding:2px 8px; border-radius:4px; font-size:10px; margin:2px; }
  .rec-item { background:#030f07; border:1px solid #14532d; border-radius:6px; padding:8px 12px; margin:4px 0; font-size:12px; color:#86efac; }
  .briefing-box { background:#080c10; border:1px solid #0f1e30; border-left:4px solid #3b82f6; border-radius:0 12px 12px 0; padding:16px 20px; margin:10px 0; }

  .stat-card { background:#0a0c14; border:1px solid #0f1e20; border-radius:10px; padding:14px; text-align:center; }
  .stat-val  { font-size:26px; font-weight:700; font-family:'JetBrains Mono',monospace; }
  .stat-label{ font-size:10px; color:#334155; text-transform:uppercase; letter-spacing:1.5px; margin-top:3px; }

  .ticker { background:#0a0c10; border:1px solid #0f1e20; border-radius:8px; padding:8px 14px; margin:3px 0; font-family:'JetBrains Mono',monospace; font-size:12px; color:#94a3b8; display:flex; justify-content:space-between; }

  div.stButton > button {
    background:linear-gradient(135deg,#1e0a0a,#dc2626);
    color:white; font-weight:700; border:none; border-radius:10px;
    padding:13px 28px; font-size:15px; width:100%;
  }
  div.stButton > button:hover { opacity:0.85; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Threat Intel")
    st.markdown("---")
    st.markdown("### 🔑 Gemini API Key")
    api_key = st.text_input("Free Gemini API Key", type="password", placeholder="AIza...")
    if not api_key:
        st.info("🆓 Free at [aistudio.google.com](https://aistudio.google.com)")

    st.markdown("---")
    st.markdown("### 📡 Intelligence Sources")
    st.markdown("**Always included:**")
    st.markdown("🔓 NIST NVD (Live CVEs)")

    st.markdown("**News & Advisory feeds:**")
    selected_feeds = []
    defaults = ["bleepingcomputer", "krebs", "sans", "darkreading"]
    for fid, cfg in THREAT_FEEDS.items():
        if st.checkbox(f"📡 {cfg['name']}", value=fid in defaults, key=f"feed_{fid}"):
            selected_feeds.append(fid)

    st.markdown("---")
    st.markdown("### ⚙️ Settings")
    max_per_feed   = st.slider("Items per feed", 3, 10, 5)
    max_analyse    = st.slider("Max AI analyses", 5, 20, 10,
                                help="Each uses one Gemini API call")
    show_briefing  = st.checkbox("Generate AI briefing", value=True)
    fetch_clicked  = st.button("🔴 FETCH LIVE THREATS")

# ── Main ───────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
  <h1>🛡️ AI Threat Intelligence Dashboard</h1>
  <p>Live CVEs · Security Advisories · AI Analysis · MITRE ATT&CK · IOCs · Executive Briefing</p>
</div>
""", unsafe_allow_html=True)

# ── Fetch ──────────────────────────────────────────────────────────────────────
if fetch_clicked:
    if not api_key:
        st.error("⚠️ Add your free Gemini API key in the sidebar.")
        st.stop()

    prog = st.progress(0, text="Initialising...")
    items: list[ThreatItem] = []

    def on_fetch(done, total, name):
        prog.progress((done + 0.5) / max(total, 1), text=f"📡 Fetching: {name}...")

    with st.spinner("📡 Pulling live threat intelligence..."):
        items = fetch_all_feeds(selected_feeds, include_nvd=True,
                                max_per_feed=max_per_feed, on_progress=on_fetch)
    prog.empty()
    st.success(f"✅ Collected {len(items)} threat items")

    # AI Analysis
    analyses: list[ThreatAnalysis] = []
    a_prog = st.progress(0, text="Starting AI analysis...")
    to_analyse = items[:max_analyse]

    for i, item in enumerate(to_analyse):
        a_prog.progress((i + 1) / len(to_analyse), text=f"🤖 Analysing: {item.title[:50]}...")
        analysis = analyze_threat(item, api_key)
        analyses.append(analysis)

    a_prog.empty()

    # Briefing
    briefing = None
    if show_briefing and items:
        with st.spinner("📋 Generating executive briefing..."):
            briefing = generate_briefing(items, analyses, api_key)

    st.session_state.update({
        "items": items, "analyses": analyses, "briefing": briefing,
    })
    st.success(f"✅ AI analysed {len(analyses)} threats")

# ── Display ────────────────────────────────────────────────────────────────────
items     = st.session_state.get("items", [])
analyses  = st.session_state.get("analyses", [])
briefing  = st.session_state.get("briefing")

if items:
    sev_counts = Counter(i.severity for i in items)
    cat_counts = Counter(i.category for i in items)
    sev_order  = ["critical", "high", "medium", "low"]

    # ── KPI row ────────────────────────────────────────────────────────────────
    k1,k2,k3,k4,k5 = st.columns(5)
    kpis = [
        (len(items),               "#60a5fa", "Total Threats"),
        (sev_counts.get("critical",0), "#dc2626", "Critical"),
        (sev_counts.get("high",0),     "#f97316", "High"),
        (sev_counts.get("medium",0),   "#eab308", "Medium"),
        (len(analyses),                "#22c55e", "AI Analysed"),
    ]
    for col, (val, color, label) in zip([k1,k2,k3,k4,k5], kpis):
        with col:
            st.markdown(f'<div class="stat-card"><div class="stat-val" style="color:{color};">{val}</div><div class="stat-label">{label}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Tabs ───────────────────────────────────────────────────────────────────
    tab1,tab2,tab3,tab4,tab5 = st.tabs([
        "📋 Briefing", "🚨 Live Feed", "🔍 Deep Analysis",
        "📊 Analytics", "⚙️ CVE Tracker"
    ])

    # ── Tab 1: Briefing ────────────────────────────────────────────────────────
    with tab1:
        if briefing:
            # Threat level indicator
            total_critical = briefing.critical_count
            overall = "CRITICAL" if total_critical >= 3 else ("HIGH" if briefing.high_count >= 5 else "ELEVATED")
            ov_color = "#dc2626" if overall == "CRITICAL" else ("#f97316" if overall == "HIGH" else "#eab308")

            st.markdown(f"""
<div style="text-align:center;padding:16px;background:{ov_color}11;border:1px solid {ov_color}33;border-radius:12px;margin-bottom:20px;">
  <div style="font-size:11px;color:{ov_color};letter-spacing:3px;font-weight:700;margin-bottom:4px;">CURRENT THREAT LEVEL</div>
  <div style="font-size:42px;font-weight:700;color:{ov_color};">{overall}</div>
  <div style="font-size:12px;color:#475569;margin-top:4px;">{briefing.generated_at}</div>
</div>
""", unsafe_allow_html=True)

            st.markdown("### 📋 Executive Summary")
            st.markdown(f'<div class="briefing-box">{briefing.executive_summary}</div>', unsafe_allow_html=True)

            col_left, col_right = st.columns(2)
            with col_left:
                st.markdown("### 🎯 Key Threats Right Now")
                for threat in briefing.key_threats:
                    st.markdown(f'<div class="ticker"><span>⚠️ {threat}</span></div>', unsafe_allow_html=True)

                st.markdown("### 📈 Trending TTPs")
                chips = "".join([f'<span class="mitre">{t}</span>' for t in briefing.trending_ttps])
                st.markdown(chips, unsafe_allow_html=True)

            with col_right:
                st.markdown("### ✅ Recommended Actions")
                for rec in briefing.recommended_actions:
                    st.markdown(f'<div class="rec-item">✅ {rec}</div>', unsafe_allow_html=True)

                st.markdown("### 🌐 Threat Landscape")
                st.markdown(f'<div class="briefing-box" style="border-left-color:#22c55e;">{briefing.threat_landscape}</div>', unsafe_allow_html=True)
        else:
            st.info("Enable 'Generate AI briefing' in the sidebar and re-fetch to see the executive briefing.")

    # ── Tab 2: Live Feed ───────────────────────────────────────────────────────
    with tab2:
        st.markdown("### 🚨 Live Threat Feed")
        fc1, fc2 = st.columns(2)
        with fc1:
            filter_sev = st.multiselect("Severity", sev_order,
                                         default=["critical","high","medium"])
        with fc2:
            filter_cat = st.multiselect("Category",
                                         list(set(i.category for i in items)),
                                         default=list(set(i.category for i in items)))

        filtered = [i for i in items if i.severity in filter_sev and i.category in filter_cat]

        for item in filtered:
            cfg      = SEVERITY.get(item.severity, SEVERITY["low"])
            cat_cfg  = THREAT_CATEGORIES.get(item.category, {"icon":"🔍","color":"#94a3b8"})
            col      = cfg["color"]
            cve_html = "".join([f'<span class="tag">{c}</span>' for c in item.cve_ids[:3]])
            cvss_str = f"CVSS: {item.cvss_score:.1f}" if item.cvss_score > 0 else ""

            st.markdown(f"""
<div class="threat-{item.severity}">
  <div class="threat-title">{cat_cfg['icon']} {item.title}</div>
  <div class="threat-desc">{item.description[:200]}{'...' if len(item.description)>200 else ''}</div>
  <div class="threat-meta">
    <span class="sev-pill" style="background:{col}22;color:{col};border:1px solid {col}44;">{cfg['emoji']} {item.severity.upper()}</span>
    <span>📡 {item.source}</span>
    {f'<span style="color:{col};font-weight:600;">{cvss_str}</span>' if cvss_str else ''}
    <span>📅 {item.published[:10] if item.published else '—'}</span>
    {f'<a href="{item.url}" target="_blank" style="color:#60a5fa;font-size:11px;">🔗 Source</a>' if item.url else ''}
  </div>
  {('<div style="margin-top:6px;">' + cve_html + '</div>') if cve_html else ''}
</div>
""", unsafe_allow_html=True)

    # ── Tab 3: Deep Analysis ───────────────────────────────────────────────────
    with tab3:
        st.markdown("### 🔍 AI Deep Analysis")
        st.caption(f"Detailed analysis for {len(analyses)} highest-priority threats")

        # Analysis lookup
        item_map = {i.id: i for i in items}

        urgency_order = ["immediate","this-week","monitor","informational"]
        sorted_analyses = sorted(analyses,
            key=lambda a: urgency_order.index(a.urgency) if a.urgency in urgency_order else 4)

        for analysis in sorted_analyses:
            item = item_map.get(analysis.item_id)
            sev_cfg  = SEVERITY.get(analysis.severity, SEVERITY["low"])
            urg_colors = {"immediate":"#dc2626","this-week":"#f97316","monitor":"#eab308","informational":"#22c55e"}
            urg_color  = urg_colors.get(analysis.urgency, "#94a3b8")

            mitre_html = "".join([f'<span class="mitre">{t}</span>' for t in analysis.mitre_tactics])
            ioc_html   = "".join([f'<span class="ioc">{i}</span>' for i in analysis.iocs[:4]])
            sys_html   = "".join([f'<span class="tag">{s}</span>' for s in analysis.affected_systems[:4]])

            with st.expander(f"{sev_cfg['emoji']} {analysis.title[:80]}", expanded=analysis.urgency=="immediate"):
                col_a, col_b = st.columns([3,1])
                with col_a:
                    st.markdown(f"**🤖 AI Summary:** {analysis.ai_summary}")
                    st.markdown(f"**💥 Impact:** {analysis.impact}")
                    if mitre_html:
                        st.markdown(f"**🎯 MITRE ATT&CK:** {mitre_html}", unsafe_allow_html=True)
                    if sys_html:
                        st.markdown(f"**💻 Affected:** {sys_html}", unsafe_allow_html=True)
                    if ioc_html:
                        st.markdown(f"**🔍 IOCs:** {ioc_html}", unsafe_allow_html=True)
                    if analysis.recommendations:
                        st.markdown("**✅ Recommendations:**")
                        for r in analysis.recommendations:
                            st.markdown(f'<div class="rec-item">✅ {r}</div>', unsafe_allow_html=True)
                with col_b:
                    st.markdown(f'<div class="stat-card"><div class="stat-val" style="color:{urg_color};font-size:14px;">{analysis.urgency.upper()}</div><div class="stat-label">Urgency</div></div><br>', unsafe_allow_html=True)
                    st.markdown(f'<div class="stat-card"><div class="stat-val" style="font-size:14px;color:#a78bfa;">{analysis.threat_actor}</div><div class="stat-label">Threat Actor</div></div><br>', unsafe_allow_html=True)
                    st.markdown(f'<div class="stat-card"><div class="stat-val" style="font-size:16px;color:#22c55e;">{analysis.confidence}%</div><div class="stat-label">AI Confidence</div></div>', unsafe_allow_html=True)

    # ── Tab 4: Analytics ───────────────────────────────────────────────────────
    with tab4:
        st.markdown("### 📊 Threat Analytics")
        col_c1, col_c2 = st.columns(2)

        with col_c1:
            # Severity pie
            sev_labels = [s for s in sev_order if sev_counts.get(s,0) > 0]
            sev_values = [sev_counts[s] for s in sev_labels]
            sev_colors = [SEVERITY[s]["color"] for s in sev_labels]
            fig_sev = go.Figure(go.Pie(
                labels=sev_labels, values=sev_values,
                marker=dict(colors=sev_colors), hole=0.45,
                textinfo="label+value",
            ))
            fig_sev.update_layout(
                paper_bgcolor="#060709", plot_bgcolor="#060709",
                font_color="#94a3b8", height=300, showlegend=False,
                margin=dict(t=20,b=10,l=10,r=10), title="Threats by Severity",
            )
            st.plotly_chart(fig_sev, use_container_width=True)

        with col_c2:
            # Category bar
            top_cats = sorted(cat_counts.items(), key=lambda x: -x[1])[:8]
            cat_cfg_list = [THREAT_CATEGORIES.get(c[0], {"icon":"🔍","color":"#60a5fa"}) for c in top_cats]
            fig_cat = go.Figure(go.Bar(
                y=[f"{THREAT_CATEGORIES.get(c,'🔍' if c not in THREAT_CATEGORIES else THREAT_CATEGORIES[c])['icon'] if c in THREAT_CATEGORIES else '🔍'} {c}" for c,_ in top_cats],
                x=[v for _,v in top_cats],
                orientation="h",
                marker_color=[c["color"] for c in cat_cfg_list],
                opacity=0.85,
            ))
            fig_cat.update_layout(
                paper_bgcolor="#060709", plot_bgcolor="#060709",
                font_color="#94a3b8", height=300,
                xaxis=dict(title="Count", gridcolor="#0f1e20"),
                margin=dict(t=20,b=10,l=10,r=10), title="Threats by Category",
            )
            st.plotly_chart(fig_cat, use_container_width=True)

        # MITRE ATT&CK coverage
        st.markdown("### 🎯 MITRE ATT&CK Tactic Coverage")
        tactic_counts = Counter()
        for a in analyses:
            tactic_counts.update(a.mitre_tactics)

        if tactic_counts:
            tac_df = pd.DataFrame(tactic_counts.most_common(10), columns=["Tactic","Count"])
            fig_tac = go.Figure(go.Bar(
                x=tac_df["Tactic"], y=tac_df["Count"],
                marker_color="#a855f7", opacity=0.85,
                text=tac_df["Count"], textposition="outside",
            ))
            fig_tac.update_layout(
                paper_bgcolor="#060709", plot_bgcolor="#060709",
                font_color="#94a3b8", height=300,
                yaxis=dict(title="Frequency", gridcolor="#0f1e20"),
                xaxis=dict(gridcolor="#0f1e20", tickangle=-30),
                margin=dict(t=20,b=60,l=10,r=10),
            )
            st.plotly_chart(fig_tac, use_container_width=True)

        # Source distribution
        st.markdown("### 📡 Sources")
        src_counts = Counter(i.source for i in items)
        src_df = pd.DataFrame(src_counts.most_common(), columns=["Source","Count"])
        st.dataframe(src_df, use_container_width=True, hide_index=True)

    # ── Tab 5: CVE Tracker ─────────────────────────────────────────────────────
    with tab5:
        st.markdown("### 🔓 CVE Tracker")
        cve_items = [i for i in items if i.cve_ids or i.source == "NIST NVD"]
        if cve_items:
            cve_rows = []
            for item in cve_items:
                for cve_id in (item.cve_ids or ["—"]):
                    cve_rows.append({
                        "CVE ID":     cve_id,
                        "Title":      item.title[:60] + "...",
                        "CVSS":       item.cvss_score if item.cvss_score else "—",
                        "Severity":   item.severity.upper(),
                        "Published":  item.published[:10] if item.published else "—",
                        "Affected":   ", ".join(item.affected[:2]) if item.affected else "—",
                        "Source":     item.source,
                    })
            cve_df = pd.DataFrame(cve_rows)
            if not cve_df.empty:
                cve_df = cve_df.sort_values("CVSS", ascending=False)
            st.dataframe(cve_df, use_container_width=True, hide_index=True)
        else:
            st.info("No CVEs fetched. Enable NIST NVD feed and re-fetch.")

    # ── Export ─────────────────────────────────────────────────────────────────
    st.markdown("---")
    export = {
        "generated_at": str(__import__("datetime").datetime.now()),
        "briefing":  asdict(briefing) if briefing else None,
        "threats":   [asdict(i) for i in items],
        "analyses":  [asdict(a) for a in analyses],
    }
    st.download_button(
        "⬇️ Export Full Intelligence Report (.json)",
        data=json.dumps(export, indent=2, default=str),
        file_name="threat_intel_report.json",
        mime="application/json",
    )

else:
    # Empty state
    st.markdown("""
<div style="text-align:center;padding:50px 20px;">
  <div style="font-size:72px;margin-bottom:16px;">🛡️</div>
  <h3 style="color:#334155;">Select sources in sidebar and click FETCH LIVE THREATS</h3>
  <p style="color:#1e293b;font-size:14px;max-width:540px;margin:0 auto;">
    Pulls live CVEs from NIST NVD, security advisories, and news from top infosec sources.
    Gemini AI analyses each threat for impact, affected systems, MITRE ATT&CK tactics,
    IOCs, and recommended defensive actions.
  </p>
</div>
""", unsafe_allow_html=True)

    cols = st.columns(4)
    for col, (icon, title, desc) in zip(cols, [
        ("🔓","Live CVEs","Real-time NVD vulnerability feed with CVSS scores"),
        ("🤖","AI Analysis","MITRE ATT&CK mapping, IOCs, impact assessment"),
        ("📋","Briefing","Executive threat summary for leadership"),
        ("📊","Analytics","Severity charts, category breakdown, source stats"),
    ]):
        with col:
            st.markdown(f'<div style="background:#0a0c14;border:1px solid #0f1e20;border-radius:10px;padding:14px;text-align:center;"><div style="font-size:24px;margin-bottom:6px;">{icon}</div><div style="font-weight:600;color:#e2e8f0;margin-bottom:4px;">{title}</div><div style="font-size:11px;color:#334155;">{desc}</div></div>', unsafe_allow_html=True)
