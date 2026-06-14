import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import os
from datetime import datetime

#Page Configuration
st.set_page_config(
    page_title="SentinelAI — Insider Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# GLOBAL CSS — dark cybersecurity aesthetic
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0a0d14;
    color: #c9d1d9;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #1c2333;
}
section[data-testid="stSidebar"] * { color: #8b949e !important; }
section[data-testid="stSidebar"] .stRadio label { color: #c9d1d9 !important; }
section[data-testid="stSidebar"] h1, section[data-testid="stSidebar"] h2 { color: #58a6ff !important; }

/* Main background */
.main .block-container {
    background-color: #0a0d14;
    padding: 1.5rem 2rem;
    max-width: 1400px;
}

/* Metric cards */
.metric-card {
    background: #0d1117;
    border: 1px solid #1c2333;
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 12px;
}
.metric-card.critical { border-left: 4px solid #f85149; }
.metric-card.high     { border-left: 4px solid #e3b341; }
.metric-card.medium   { border-left: 4px solid #388bfd; }
.metric-card.low      { border-left: 4px solid #3fb950; }
.metric-card.neutral  { border-left: 4px solid #58a6ff; }
.metric-value { font-family:'JetBrains Mono',monospace; font-size:2rem; font-weight:600; color:#e6edf3; }
.metric-label { font-size:0.75rem; color:#8b949e; text-transform:uppercase; letter-spacing:0.1em; margin-top:4px; }
.metric-delta { font-size:0.8rem; margin-top:6px; }
.delta-up   { color:#f85149; }
.delta-down { color:#3fb950; }

/* Alert card */
.alert-card {
    background: #0d1117;
    border: 1px solid #1c2333;
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 16px;
}
.alert-card.critical { border-left: 4px solid #f85149; background: #110d0d; }
.alert-card.high     { border-left: 4px solid #e3b341; background: #110f0a; }
.alert-card.medium   { border-left: 4px solid #388bfd; background: #090e17; }
.alert-card.low      { border-left: 4px solid #3fb950; background: #090e0a; }

.alert-header {
    display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;
}
.alert-title {
    font-family:'JetBrains Mono',monospace;
    font-size:0.85rem; font-weight:600; color:#e6edf3; letter-spacing:0.05em;
}
.badge {
    font-family:'JetBrains Mono',monospace;
    font-size:0.7rem; font-weight:700;
    padding:3px 10px; border-radius:4px;
    text-transform:uppercase; letter-spacing:0.08em;
}
.badge-critical { background:#f8514920; color:#f85149; border:1px solid #f8514940; }
.badge-high     { background:#e3b34120; color:#e3b341; border:1px solid #e3b34140; }
.badge-medium   { background:#388bfd20; color:#388bfd; border:1px solid #388bfd40; }
.badge-low      { background:#3fb95020; color:#3fb950; border:1px solid #3fb95040; }

.alert-meta { font-size:0.8rem; color:#8b949e; margin-bottom:10px; font-family:'Inter',sans-serif; }
.alert-meta span { color:#c9d1d9; margin-left:4px; }

.context-item {
    font-size:0.8rem; color:#8b949e; padding:3px 0;
    display:flex; align-items:flex-start; gap:8px;
}
.context-item::before { content:'▸'; color:#388bfd; flex-shrink:0; }
.context-item.critical::before { color:#f85149; }
.context-item.high::before    { color:#e3b341; }

.rec-box {
    background: #161b22;
    border: 1px solid #1c2333;
    border-radius:6px;
    padding:10px 14px;
    margin-top:10px;
    font-size:0.78rem;
    color:#8b949e;
    font-family:'JetBrains Mono',monospace;
}
.rec-box .rec-label { color:#3fb950; font-weight:600; margin-bottom:4px; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.1em; }
.rec-step { color:#c9d1d9; margin-bottom:2px; }

.impact-box {
    background: #161b22;
    border: 1px solid #1c2333;
    border-radius:6px;
    padding:10px 14px;
    margin-top:8px;
    font-size:0.78rem;
    color:#8b949e;
    font-family:'Inter',sans-serif;
    line-height:1.6;
}
.impact-box .impact-label { color:#e3b341; font-weight:600; margin-bottom:4px; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.1em; font-family:'JetBrains Mono',monospace; }

/* Score bar */
.score-bar-wrap { margin:10px 0; }
.score-bar-bg { background:#1c2333; border-radius:4px; height:6px; width:100%; overflow:hidden; }
.score-bar-fill { height:6px; border-radius:4px; transition:width 0.5s; }

/* Section header */
.section-header {
    font-family:'JetBrains Mono',monospace;
    font-size:0.72rem; color:#8b949e;
    text-transform:uppercase; letter-spacing:0.15em;
    border-bottom:1px solid #1c2333;
    padding-bottom:8px; margin:24px 0 16px 0;
}

/* Page title */
.page-title {
    font-family:'Inter',sans-serif;
    font-size:1.6rem; font-weight:700; color:#e6edf3;
    margin-bottom:4px;
}
.page-subtitle { font-size:0.85rem; color:#8b949e; margin-bottom:24px; }

/* Logo/brand in sidebar */
.brand {
    font-family:'JetBrains Mono',monospace;
    font-size:1.1rem; font-weight:700;
    color:#58a6ff !important;
    margin-bottom:4px;
}
.brand-sub {
    font-size:0.7rem; color:#8b949e !important;
    letter-spacing:0.12em; text-transform:uppercase;
    margin-bottom:20px;
}

/* Dataframe styling */
.stDataFrame { border: 1px solid #1c2333 !important; border-radius:6px !important; }

/* Plotly chart background fix */
.js-plotly-plot { border-radius: 8px; }

/* Select box */
.stSelectbox label { color:#8b949e !important; font-size:0.8rem !important; }

/* Score badge */
.score-badge {
    font-family:'JetBrains Mono',monospace;
    font-size:1.4rem; font-weight:700;
    display:inline-block;
}

/* Divider */
.cyber-divider {
    border:none; border-top:1px solid #1c2333;
    margin: 20px 0;
}

/* Metrics grid */
.metrics-grid { display:flex; gap:12px; margin-bottom:20px; flex-wrap:wrap; }

/* Tag */
.tag {
    display:inline-block;
    font-size:0.65rem; font-weight:600;
    font-family:'JetBrains Mono',monospace;
    padding:2px 8px; border-radius:3px;
    background:#161b22; border:1px solid #1c2333;
    color:#8b949e; margin-right:6px; margin-bottom:4px;
    text-transform:uppercase; letter-spacing:0.07em;
}
.tag-sensitive { background:#f8514915; border-color:#f8514940; color:#f85149; }
.tag-night     { background:#388bfd15; border-color:#388bfd40; color:#388bfd; }
.tag-unauth    { background:#e3b34115; border-color:#e3b34140; color:#e3b341; }
.tag-ml        { background:#bc8cff15; border-color:#bc8cff40; color:#bc8cff; }

/* Table-like user profile */
.profile-row { display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid #1c2333; font-size:0.8rem; }
.profile-label { color:#8b949e; }
.profile-value { color:#c9d1d9; font-family:'JetBrains Mono',monospace; }
</style>
""", unsafe_allow_html=True)

# DATA LOADING

@st.cache_data
def load_data():
    base = os.path.dirname(os.path.abspath(__file__))
    df = pd.read_csv(os.path.join(base, 'final_incident_report_v2.csv'))
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['date'] = df['timestamp'].dt.date
    # Parse context bullets back to list
    df['bullets_list'] = df['context_bullets'].apply(
        lambda x: [b.replace('• ','').strip() for b in str(x).split('\n') if b.strip()] if pd.notna(x) else []
    )
    return df

@st.cache_data
def load_users():
    base = os.path.dirname(os.path.abspath(__file__))
    return pd.read_csv(os.path.join(base, 'user_profiles.csv'))

@st.cache_data
def load_metrics():
    base = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base, 'evaluation_metrics.json')
    with open(path) as f:
        return json.load(f)

df      = load_data()
users   = load_users()
metrics = load_metrics()

# HELPERS

LEVEL_COLORS = {'Critical':'#f85149','High':'#e3b341','Medium':'#388bfd','Low':'#3fb950'}
LEVEL_BG     = {'Critical':'#110d0d','High':'#110f0a','Medium':'#090e17','Low':'#090e0a'}

def score_color(score):
    if score >= 85: return '#f85149'
    if score >= 65: return '#e3b341'
    if score >= 40: return '#388bfd'
    return '#3fb950'

def level_badge(level):
    return f'<span class="badge badge-{level.lower()}">{level}</span>'

def render_alert_card(row, alert_num):
    level   = row['final_risk_level']
    score   = row['final_risk_score']
    color   = LEVEL_COLORS[level]
    ts      = row['timestamp']
    hour    = ts.hour
    ampm    = "AM" if hour < 12 else "PM"
    hour12  = hour % 12 or 12
    time_str = f"{ts.strftime('%Y-%m-%d')} {hour12:02d}:{ts.strftime('%M')} {ampm}"

    # Tags
    tags = ''
    if row.get('resource_sensitivity') == 'high':
        tags += '<span class="tag tag-sensitive">HIGH SENSITIVITY</span>'
    if row.get('is_night'):
        tags += '<span class="tag tag-night">NIGHT ACCESS</span>'
    if row.get('unauthorized'):
        tags += '<span class="tag tag-unauth">UNAUTHORIZED</span>'
    if row.get('ml_flag'):
        tags += '<span class="tag tag-ml">ML ANOMALY</span>'
    if row.get('is_weekend'):
        tags += '<span class="tag tag-night">WEEKEND</span>'

    # Context bullets
    bullets_html = ''
    for b in row['bullets_list']:
        item_class = 'critical' if level == 'Critical' else ('high' if level == 'High' else '')
        bullets_html += f'<div class="context-item {item_class}">{b}</div>'

    # Recommendation steps
    rec_steps = [s.strip() for s in str(row['recommendation']).split('|') if s.strip()]
    rec_html  = '<div class="rec-label">⚡ Recommended Actions</div>'
    for i, step in enumerate(rec_steps, 1):
        rec_html += f'<div class="rec-step">{i}. {step}</div>'

    # Score bar
    bar_color = color
    bar_width  = score

    # Business impact (trimmed)
    impact_text = str(row['business_impact'])
    if len(impact_text) > 400:
        impact_text = impact_text[:400] + '…'

    action_display = str(row['action']).replace('_', ' ').title()
    job_title = str(row.get('job_title', 'Unknown')).replace('nan','Unknown')

    html = f"""
    <div class="alert-card {level.lower()}">
      <div class="alert-header">
        <div>
          <div style="color:{color};font-family:'JetBrains Mono',monospace;font-size:0.65rem;
               text-transform:uppercase;letter-spacing:0.12em;margin-bottom:4px;">
            Alert #{alert_num:02d}
          </div>
          <div class="alert-title">⚠ {row.get('alert_title','SECURITY EVENT')}</div>
        </div>
        <div style="text-align:right;">
          {level_badge(level)}
          <div style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
               font-weight:700;color:{color};margin-top:6px;">{score:.0f}<span style="font-size:0.8rem;color:#8b949e;">/100</span></div>
        </div>
      </div>

      <div class="score-bar-wrap">
        <div class="score-bar-bg">
          <div class="score-bar-fill" style="width:{bar_width}%;background:{bar_color};"></div>
        </div>
      </div>

      <div style="margin-bottom:10px;">{tags}</div>

      <div class="alert-meta">
        👤 User: <span>{row['username']}</span> &nbsp;|&nbsp;
        🏢 Dept: <span>{row['department']}</span> &nbsp;|&nbsp;
        💼 Role: <span>{job_title}</span> &nbsp;|&nbsp;
        🕐 Tenure: <span>{int(row.get('tenure_months',0))} mo</span>
      </div>
      <div class="alert-meta">
        ⚡ Action: <span>{action_display}</span> &nbsp;on&nbsp;
        🗄 Resource: <span>{row['resource']}</span> &nbsp;|&nbsp;
        🕐 Time: <span>{time_str}</span> &nbsp;|&nbsp;
        📊 Confidence: <span>{int(row.get('confidence',75))}%</span>
      </div>

      <hr class="cyber-divider">

      <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
           color:#8b949e;text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">
        Context Signals
      </div>
      {bullets_html if bullets_html else '<div class="context-item">No additional context signals detected.</div>'}

      <div class="impact-box">
        <div class="impact-label">💰 Business Impact</div>
        {impact_text}
      </div>

      <div class="rec-box">
        {rec_html}
      </div>
    </div>
    """
    return html

# SIDEBAR

with st.sidebar:
    st.markdown('<div class="brand">🛡 SentinelAI</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-sub">Insider Threat Detection</div>', unsafe_allow_html=True)

    page = st.radio(
        "Navigation",
        ["📊 Dashboard", "🚨 Critical Alerts", "🔍 Investigation", "📈 Analytics", "📋 Incident Report", "🧪 Evaluation Metrics"],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown('<div style="font-size:0.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;">System Status</div>', unsafe_allow_html=True)
    st.markdown(f'<div style="font-size:0.75rem;color:#3fb950;margin-top:4px;">● MONITORING ACTIVE</div>', unsafe_allow_html=True)
    st.markdown(f'<div style="font-size:0.75rem;color:#8b949e;margin-top:2px;">Events Analysed: {metrics["total_events"]:,}</div>', unsafe_allow_html=True)
    st.markdown(f'<div style="font-size:0.75rem;color:#8b949e;margin-top:2px;">Coverage: Apr 2025 – Apr 2026</div>', unsafe_allow_html=True)
    st.markdown(f'<div style="font-size:0.75rem;color:#f85149;margin-top:2px;">⚠ Critical Open: {metrics["critical_count"]}</div>', unsafe_allow_html=True)
    st.markdown("---")
    st.markdown(f'<div style="font-size:0.75rem;color:#3fb950;margin-top:4px;">Developed By </div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:0.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;"> Pavanakumar Harigadde</div>', unsafe_allow_html=True)


#  PAGE 1: DASHBOARD

if page == "📊 Dashboard":
    st.markdown('<div class="page-title">🛡 Data Access Audit & Insider Threat Detection</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Real-time anomaly monitoring across databases, APIs, file shares and cloud resources</div>', unsafe_allow_html=True)

    # ── KPI Row ──────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    kpis = [
        (c1, "Total Events", f"{metrics['total_events']:,}", "neutral", None),
        (c2, "Critical Alerts", f"{metrics['critical_count']}", "critical", "Immediate action"),
        (c3, "High Risk", f"{metrics['high_count']}", "high", "Escalate today"),
        (c4, "ML Anomalies", f"{metrics['ml_anomalies']:,}", "medium", "Isolation Forest"),
        (c5, "Unauthorized", f"{metrics['unauth_count']:,}", "high", "Role violations"),
    ]
    for col, label, val, cls, sub in kpis:
        with col:
            sub_html = f'<div class="metric-delta" style="color:#8b949e;">{sub}</div>' if sub else ''
            st.markdown(f"""
            <div class="metric-card {cls}">
              <div class="metric-value">{val}</div>
              <div class="metric-label">{label}</div>
              {sub_html}
            </div>""", unsafe_allow_html=True)

    # ── Charts Row ────────────────────────────────────────
    col_l, col_r = st.columns([1, 1])

    with col_l:
        # Risk distribution donut
        lvl_counts = df['final_risk_level'].value_counts().reindex(['Critical','High','Medium','Low'], fill_value=0)
        fig_donut = go.Figure(go.Pie(
            labels=lvl_counts.index,
            values=lvl_counts.values,
            hole=0.6,
            marker=dict(colors=['#f85149','#e3b341','#388bfd','#3fb950'],
                        line=dict(color='#0a0d14', width=2)),
            textinfo='label+percent',
            textfont=dict(family='JetBrains Mono', size=11, color='#c9d1d9'),
        ))
        fig_donut.update_layout(
            title=dict(text='Risk Level Distribution', font=dict(color='#c9d1d9', size=14, family='Inter'), x=0.02),
            paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
            legend=dict(font=dict(color='#8b949e'), bgcolor='#0d1117'),
            margin=dict(t=40, b=20, l=20, r=20), height=320,
            annotations=[dict(text=f'<b>{metrics["total_events"]}</b><br>events', x=0.5, y=0.5,
                              font=dict(size=13, color='#e6edf3', family='JetBrains Mono'),
                              showarrow=False)],
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with col_r:
        # Timeline of risk events
        daily = df.groupby(['date','final_risk_level']).size().reset_index(name='count')
        daily['date'] = pd.to_datetime(daily['date'])
        fig_line = go.Figure()
        for lvl in ['Critical','High','Medium']:
            d = daily[daily['final_risk_level']==lvl]
            fig_line.add_trace(go.Scatter(
                x=d['date'], y=d['count'], mode='lines',
                name=lvl, line=dict(color=LEVEL_COLORS[lvl], width=2),
                fill='tozeroy', fillcolor=LEVEL_COLORS[lvl],
            ))
        fig_line.update_layout(
            title=dict(text='Alert Timeline (Apr 2025 – Apr 2026)', font=dict(color='#c9d1d9', size=14, family='Inter'), x=0.02),
            paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
            xaxis=dict(gridcolor='#1c2333', color='#8b949e', tickfont=dict(family='JetBrains Mono', size=10)),
            yaxis=dict(gridcolor='#1c2333', color='#8b949e', tickfont=dict(family='JetBrains Mono', size=10)),
            legend=dict(font=dict(color='#8b949e'), bgcolor='#0d1117'),
            margin=dict(t=40, b=20, l=20, r=20), height=320,
            hovermode='x unified',
        )
        st.plotly_chart(fig_line, use_container_width=True)

    # ── Second Chart Row ──────────────────────────────────
    col_a, col_b = st.columns([1, 1])

    with col_a:
        # Dept risk heatmap
        dept_risk = df.groupby('department')['final_risk_score'].mean().sort_values(ascending=True)
        fig_dept = go.Figure(go.Bar(
            x=dept_risk.values, y=dept_risk.index,
            orientation='h',
            marker=dict(
                color=dept_risk.values,
                colorscale=[[0,'#3fb950'],[0.4,'#388bfd'],[0.7,'#e3b341'],[1,'#f85149']],
                showscale=False,
            ),
            text=[f'{v:.1f}' for v in dept_risk.values],
            textfont=dict(family='JetBrains Mono', size=10, color='#c9d1d9'),
            textposition='outside',
        ))
        fig_dept.update_layout(
            title=dict(text='Avg Risk Score by Department', font=dict(color='#c9d1d9', size=14, family='Inter'), x=0.02),
            paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
            xaxis=dict(gridcolor='#1c2333', color='#8b949e', range=[0, dept_risk.max()*1.2]),
            yaxis=dict(color='#8b949e', tickfont=dict(family='JetBrains Mono', size=10)),
            margin=dict(t=40, b=20, l=10, r=60), height=360,
        )
        st.plotly_chart(fig_dept, use_container_width=True)

    with col_b:
        # Action type breakdown
        act_risk = df.groupby('action').agg(
            count=('final_risk_score','count'),
            avg_score=('final_risk_score','mean'),
        ).sort_values('avg_score', ascending=False).reset_index()
        act_risk['action_label'] = act_risk['action'].str.replace('_',' ').str.title()

        fig_act = go.Figure()
        fig_act.add_trace(go.Bar(
            name='Avg Risk Score',
            x=act_risk['action_label'],
            y=act_risk['avg_score'],
            marker=dict(color=['#f85149','#e3b341','#388bfd','#3fb950','#8b949e','#58a6ff'][:len(act_risk)]),
            text=[f'{v:.0f}' for v in act_risk['avg_score']],
            textfont=dict(family='JetBrains Mono', size=10, color='#c9d1d9'),
            textposition='outside',
            yaxis='y',
        ))
        fig_act.add_trace(go.Scatter(
            name='Event Count',
            x=act_risk['action_label'],
            y=act_risk['count'],
            mode='markers+lines',
            marker=dict(color='#bc8cff', size=8),
            line=dict(color='#bc8cff', dash='dot'),
            yaxis='y2',
        ))
        fig_act.update_layout(
            title=dict(text='Risk Score & Volume by Action Type', font=dict(color='#c9d1d9', size=14, family='Inter'), x=0.02),
            paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
            xaxis=dict(color='#8b949e', tickfont=dict(family='JetBrains Mono', size=10), gridcolor='#1c2333'),
            yaxis=dict(color='#8b949e', title=dict(text='Avg Risk Score', font=dict(color='#8b949e', size=11)), gridcolor='#1c2333'),
            yaxis2=dict(color='#bc8cff', title=dict(text='Event Count', font=dict(color='#bc8cff', size=11)),
                        overlaying='y', side='right', showgrid=False),
            legend=dict(font=dict(color='#8b949e'), bgcolor='#0d1117'),
            margin=dict(t=40, b=20, l=20, r=60), height=360,
        )
        st.plotly_chart(fig_act, use_container_width=True)

    # ── Top 10 Events Table ────────────────────────────────
    st.markdown('<div class="section-header">🔴 Top 10 Highest Risk Events</div>', unsafe_allow_html=True)
    top10 = df.nlargest(10, 'final_risk_score')[
        ['timestamp','username','department','action','resource','final_risk_score','final_risk_level','confidence']
    ].copy()
    top10.columns = ['Timestamp','User','Department','Action','Resource','Score','Level','Confidence%']
    top10['Score'] = top10['Score'].map('{:.0f}'.format)
    top10['Timestamp'] = top10['Timestamp'].dt.strftime('%Y-%m-%d %H:%M')
    st.dataframe(top10, use_container_width=True, hide_index=True)


#  PAGE 2: CRITICAL ALERTS

elif page == "🚨 Critical Alerts":
    st.markdown('<div class="page-title">🚨 Critical & High Risk Alerts</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Events requiring immediate or priority investigation</div>', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔴 Critical", "🟡 High"])

    with tab1:
        critical_df = df[df['final_risk_level']=='Critical'].sort_values('final_risk_score', ascending=False).reset_index(drop=True)
        st.markdown(f'<div style="font-size:0.8rem;color:#f85149;margin-bottom:16px;">⚠ {len(critical_df)} Critical alerts — immediate investigation required</div>', unsafe_allow_html=True)
        for i, row in critical_df.iterrows():
            st.markdown(render_alert_card(row, i+1), unsafe_allow_html=True)

    with tab2:
        high_df = df[df['final_risk_level']=='High'].sort_values('final_risk_score', ascending=False).reset_index(drop=True)
        st.markdown(f'<div style="font-size:0.8rem;color:#e3b341;margin-bottom:16px;">⚡ {len(high_df)} High risk alerts — prioritise within 24 hours</div>', unsafe_allow_html=True)
        for i, row in high_df.head(20).iterrows():
            st.markdown(render_alert_card(row, i+1), unsafe_allow_html=True)
        if len(high_df) > 20:
            st.caption(f'Showing top 20 of {len(high_df)} high-risk alerts. Use Investigation page to search all.')


#  PAGE 3: INVESTIGATION WORKBENCH

elif page == "🔍 Investigation":
    st.markdown('<div class="page-title">🔍 Investigation Workbench</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Deep-dive into individual users and events</div>', unsafe_allow_html=True)

    col_s1, col_s2 = st.columns([2, 1])
    with col_s1:
        selected_user = st.selectbox("Select User to Investigate", sorted(df['username'].unique()))
    with col_s2:
        level_filter = st.selectbox("Filter by Risk Level", ["All", "Critical", "High", "Medium", "Low"])

    user_df = df[df['username'] == selected_user].copy()
    if level_filter != "All":
        user_df = user_df[user_df['final_risk_level'] == level_filter]
    user_df = user_df.sort_values('final_risk_score', ascending=False).reset_index(drop=True)

    # User profile panel
    user_profile = users[users['username'] == selected_user]
    if not user_profile.empty:
        p = user_profile.iloc[0]
        col_prof, col_events = st.columns([1, 2])

        with col_prof:
            highest = df[df['username']==selected_user]['final_risk_level'].value_counts()
            risk_lvl = 'Critical' if 'Critical' in highest.index else ('High' if 'High' in highest.index else ('Medium' if 'Medium' in highest.index else 'Low'))
            rc = LEVEL_COLORS.get(risk_lvl, '#8b949e')

            st.markdown(f"""
            <div class="metric-card {risk_lvl.lower()}">
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#8b949e;
                   text-transform:uppercase;letter-spacing:0.12em;margin-bottom:10px;">User Profile</div>
              <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;margin-bottom:2px;">{selected_user}</div>
              <div style="font-size:0.8rem;color:#8b949e;margin-bottom:12px;">{p.get('email','N/A')}</div>
              <div class="profile-row"><span class="profile-label">Department</span><span class="profile-value">{p.get('department','N/A')}</span></div>
              <div class="profile-row"><span class="profile-label">Job Title</span><span class="profile-value">{p.get('job_title','N/A')}</span></div>
              <div class="profile-row"><span class="profile-label">Privilege</span><span class="profile-value">{p.get('privilege_level','N/A')}</span></div>
              <div class="profile-row"><span class="profile-label">Systems Access</span><span class="profile-value" style="font-size:0.7rem;">{str(p.get('systems_access','N/A')).replace('|', ' | ')}</span></div>
              <div class="profile-row"><span class="profile-label">Days Inactive</span><span class="profile-value" style="color:{'#f85149' if p.get('days_inactive',0)>=30 else '#3fb950'};">{int(p.get('days_inactive',0))} days</span></div>
              <div class="profile-row"><span class="profile-label">Hire Date</span><span class="profile-value">{p.get('hire_date','N/A')}</span></div>
              <div class="profile-row" style="border:none;"><span class="profile-label">Risk Profile</span><span class="profile-value" style="color:{rc};">{risk_lvl}</span></div>
            </div>
            """, unsafe_allow_html=True)

        with col_events:
            # Mini charts for user
            usr_all = df[df['username']==selected_user]
            user_risk_dist = usr_all['final_risk_level'].value_counts().reindex(['Critical','High','Medium','Low'],fill_value=0)
            fig_u = go.Figure(go.Bar(
                x=user_risk_dist.index, y=user_risk_dist.values,
                marker=dict(color=['#f85149','#e3b341','#388bfd','#3fb950']),
                text=user_risk_dist.values,
                textfont=dict(family='JetBrains Mono', size=11, color='#c9d1d9'),
                textposition='outside',
            ))
            fig_u.update_layout(
                title=dict(text=f'Risk Distribution — {selected_user}', font=dict(color='#c9d1d9',size=13,family='Inter'),x=0.02),
                paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
                xaxis=dict(color='#8b949e', tickfont=dict(family='JetBrains Mono',size=10)),
                yaxis=dict(color='#8b949e', gridcolor='#1c2333'),
                margin=dict(t=40,b=20,l=20,r=20), height=220,
            )
            st.plotly_chart(fig_u, use_container_width=True)

            usr_res = usr_all.groupby('resource')['final_risk_score'].mean().sort_values(ascending=False)
            fig_res = go.Figure(go.Bar(
                x=usr_res.index, y=usr_res.values,
                marker=dict(color='#388bfd'),
                text=[f'{v:.0f}' for v in usr_res.values],
                textfont=dict(family='JetBrains Mono',size=10,color='#c9d1d9'),
                textposition='outside',
            ))
            fig_res.update_layout(
                title=dict(text='Avg Risk by Resource Accessed', font=dict(color='#c9d1d9',size=13,family='Inter'),x=0.02),
                paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
                xaxis=dict(color='#8b949e', tickfont=dict(family='JetBrains Mono',size=9)),
                yaxis=dict(color='#8b949e', gridcolor='#1c2333'),
                margin=dict(t=40,b=20,l=20,r=20), height=220,
            )
            st.plotly_chart(fig_res, use_container_width=True)

    st.markdown(f'<div class="section-header">📋 Events for {selected_user} ({len(user_df)} records)</div>', unsafe_allow_html=True)
    for i, row in user_df.head(10).iterrows():
        st.markdown(render_alert_card(row, i+1), unsafe_allow_html=True)

    if len(user_df) > 10:
        with st.expander(f"Show all {len(user_df)} events"):
            st.dataframe(user_df[['timestamp','action','resource','final_risk_score','final_risk_level','recommendation']],
                         use_container_width=True, hide_index=True)


#  PAGE 4: ANALYTICS
elif page == "📈 Analytics":
    st.markdown('<div class="page-title">📈 Threat Analytics</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Patterns, trends, and behavioural intelligence</div>', unsafe_allow_html=True)

    # Row 1
    col1, col2 = st.columns(2)

    with col1:
        # Resource risk matrix
        res_data = df.groupby(['resource','final_risk_level']).size().unstack(fill_value=0)
        for lvl in ['Critical','High','Medium','Low']:
            if lvl not in res_data.columns:
                res_data[lvl] = 0
        res_data = res_data[['Critical','High','Medium','Low']]

        fig_matrix = go.Figure()
        for lvl in ['Critical','High','Medium','Low']:
            fig_matrix.add_trace(go.Bar(
                name=lvl, x=res_data.index, y=res_data[lvl],
                marker=dict(color=LEVEL_COLORS[lvl]),
            ))
        fig_matrix.update_layout(
            barmode='stack',
            title=dict(text='Risk Breakdown by Resource', font=dict(color='#c9d1d9',size=14,family='Inter'),x=0.02),
            paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
            xaxis=dict(color='#8b949e', tickfont=dict(family='JetBrains Mono',size=9), tickangle=-30),
            yaxis=dict(color='#8b949e', gridcolor='#1c2333'),
            legend=dict(font=dict(color='#8b949e'), bgcolor='#0d1117'),
            margin=dict(t=40,b=60,l=20,r=20), height=350,
        )
        st.plotly_chart(fig_matrix, use_container_width=True)

    with col2:
        # Access hour heatmap
        df['hour'] = df['timestamp'].dt.hour
        df['weekday_name'] = df['timestamp'].dt.strftime('%a')
        days_order = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
        hour_heat = df.groupby(['weekday_name','hour'])['final_risk_score'].mean().unstack(fill_value=0)
        hour_heat = hour_heat.reindex([d for d in days_order if d in hour_heat.index])

        fig_heat = go.Figure(go.Heatmap(
            z=hour_heat.values,
            x=[f'{h:02d}:00' for h in hour_heat.columns],
            y=hour_heat.index,
            colorscale=[[0,'#0d1117'],[0.3,'#388bfd'],[0.6,'#e3b341'],[1,'#f85149']],
            showscale=True,
            colorbar=dict(tickfont=dict(color='#8b949e',family='JetBrains Mono',size=9), outlinecolor='#1c2333'),
        ))
        fig_heat.update_layout(
            title=dict(text='Avg Risk Score: Day vs Hour Heatmap', font=dict(color='#c9d1d9',size=14,family='Inter'),x=0.02),
            paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
            xaxis=dict(color='#8b949e', tickfont=dict(family='JetBrains Mono',size=8), tickangle=-45),
            yaxis=dict(color='#8b949e', tickfont=dict(family='JetBrains Mono',size=10)),
            margin=dict(t=40,b=60,l=20,r=20), height=350,
        )
        st.plotly_chart(fig_heat, use_container_width=True)

    # Row 2
    col3, col4 = st.columns(2)

    with col3:
        # Scatter: score vs tenure
        scat = df[df['final_risk_level'].isin(['Critical','High'])].copy()
        fig_scat = go.Figure(go.Scatter(
            x=scat['tenure_months'],
            y=scat['final_risk_score'],
            mode='markers',
            marker=dict(
                color=[LEVEL_COLORS[l] for l in scat['final_risk_level']],
                size=8, opacity=0.7,
                line=dict(color='#0a0d14',width=1),
            ),
            text=scat.apply(lambda r: f"{r['username']} | {r['action']} | {r['resource']}", axis=1),
            hovertemplate='<b>%{text}</b><br>Tenure: %{x} mo<br>Score: %{y}<extra></extra>',
        ))
        fig_scat.update_layout(
            title=dict(text='Risk Score vs User Tenure (Critical & High)', font=dict(color='#c9d1d9',size=14,family='Inter'),x=0.02),
            paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
            xaxis=dict(color='#8b949e', gridcolor='#1c2333', tickfont=dict(family='JetBrains Mono',size=10), title=dict(text='Tenure (months)',font=dict(color='#8b949e'))),
            yaxis=dict(color='#8b949e', gridcolor='#1c2333', tickfont=dict(family='JetBrains Mono',size=10), title=dict(text='Risk Score',font=dict(color='#8b949e'))),
            margin=dict(t=40,b=40,l=40,r=20), height=350,
        )
        st.plotly_chart(fig_scat, use_container_width=True)

    with col4:
        # Top 15 riskiest users
        top_users = df.groupby('username').agg(
            max_score=('final_risk_score','max'),
            total_events=('final_risk_score','count'),
            critical=('final_risk_level', lambda x:(x=='Critical').sum()),
            high=('final_risk_level', lambda x:(x=='High').sum()),
        ).sort_values('max_score',ascending=False).head(15).reset_index()

        fig_users = go.Figure(go.Bar(
            x=top_users['max_score'],
            y=top_users['username'],
            orientation='h',
            marker=dict(
                color=top_users['max_score'],
                colorscale=[[0,'#388bfd'],[0.5,'#e3b341'],[1,'#f85149']],
                showscale=False,
            ),
            text=[f'{v:.0f}' for v in top_users['max_score']],
            textfont=dict(family='JetBrains Mono',size=9,color='#c9d1d9'),
            textposition='outside',
            customdata=top_users[['total_events','critical','high']].values,
            hovertemplate='<b>%{y}</b><br>Max Score: %{x}<br>Total Events: %{customdata[0]}<br>Critical: %{customdata[1]}<br>High: %{customdata[2]}<extra></extra>',
        ))
        fig_users.update_layout(
            title=dict(text='Top 15 Highest-Risk Users', font=dict(color='#c9d1d9',size=14,family='Inter'),x=0.02),
            paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
            xaxis=dict(color='#8b949e', gridcolor='#1c2333', range=[0,115], tickfont=dict(family='JetBrains Mono',size=9)),
            yaxis=dict(color='#8b949e', tickfont=dict(family='JetBrains Mono',size=9), autorange='reversed'),
            margin=dict(t=40,b=20,l=10,r=60), height=380,
        )
        st.plotly_chart(fig_users, use_container_width=True)


#  PAGE 5: INCIDENT REPORT
elif page == "📋 Incident Report":
    st.markdown('<div class="page-title">📋 Incident Report</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Formal anomaly report — top 15 detected threats with full narrative</div>', unsafe_allow_html=True)

    # Report header
    today = datetime.now().strftime('%Y-%m-%d')
    critical_count = (df['final_risk_level']=='Critical').sum()
    high_count     = (df['final_risk_level']=='High').sum()

    st.markdown(f"""
    <div class="metric-card neutral" style="margin-bottom:24px;">
      <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#8b949e;
           text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">
        SentinelAI — Data Access Anomaly Report
      </div>
      <div style="display:flex;gap:40px;flex-wrap:wrap;">
        <div><div class="metric-label">Generated</div><div style="font-family:'JetBrains Mono',monospace;color:#e6edf3;font-size:0.9rem;">{today}</div></div>
        <div><div class="metric-label">Events Analysed</div><div style="font-family:'JetBrains Mono',monospace;color:#e6edf3;font-size:0.9rem;">{metrics['total_events']:,}</div></div>
        <div><div class="metric-label">Critical Threats</div><div style="font-family:'JetBrains Mono',monospace;color:#f85149;font-size:0.9rem;">{critical_count}</div></div>
        <div><div class="metric-label">High Risk</div><div style="font-family:'JetBrains Mono',monospace;color:#e3b341;font-size:0.9rem;">{high_count}</div></div>
        <div><div class="metric-label">Coverage</div><div style="font-family:'JetBrains Mono',monospace;color:#e6edf3;font-size:0.9rem;">Apr 2025 – Apr 2026</div></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Critical section
    st.markdown('<div class="section-header">🔴 CRITICAL ALERTS — Immediate Investigation</div>', unsafe_allow_html=True)
    crit_report = df[df['final_risk_level']=='Critical'].sort_values('final_risk_score', ascending=False).head(7).reset_index(drop=True)
    for i, row in crit_report.iterrows():
        st.markdown(render_alert_card(row, i+1), unsafe_allow_html=True)

    # High section
    st.markdown('<div class="section-header">🟡 HIGH RISK ALERTS — Prioritise Within 24 Hours</div>', unsafe_allow_html=True)
    high_report = df[df['final_risk_level']=='High'].sort_values('final_risk_score', ascending=False).head(8).reset_index(drop=True)
    for i, row in high_report.iterrows():
        st.markdown(render_alert_card(row, len(crit_report)+i+1), unsafe_allow_html=True)


#  PAGE 6: EVALUATION METRICS
elif page == "🧪 Evaluation Metrics":
    st.markdown('<div class="page-title">🧪 Model Evaluation & Performance</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Detection accuracy, false positive analysis, and baseline comparison</div>', unsafe_allow_html=True)

    # Model vs Naive comparison
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="section-header">Our Model (SentinelAI)</div>', unsafe_allow_html=True)
        kpis_model = [
            ("Precision", f"{metrics['model_precision']:.1%}", "critical" if metrics['model_precision']<0.75 else "low"),
            ("Recall",    f"{metrics['model_recall']:.1%}",    "critical" if metrics['model_recall']<0.70    else "low"),
            ("F1 Score",  f"{metrics['model_f1']:.2f}",        "critical" if metrics['model_f1']<0.72        else "low"),
        ]
        for label, val, cls in kpis_model:
            target_met = '✅ Target Met' if cls == 'low' else '❌ Below Target'
            target_color = '#3fb950' if cls == 'low' else '#f85149'
            st.markdown(f"""
            <div class="metric-card {cls}">
              <div class="metric-value">{val}</div>
              <div class="metric-label">{label}</div>
              <div class="metric-delta" style="color:{target_color};">{target_met}</div>
            </div>""", unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="section-header">Naive Baseline (flag all off-hours)</div>', unsafe_allow_html=True)
        kpis_naive = [
            ("Precision", f"{metrics['naive_precision']:.1%}"),
            ("Recall",    f"{metrics['naive_recall']:.1%}"),
            ("F1 Score",  f"{metrics['naive_f1']:.2f}"),
        ]
        for label, val in kpis_naive:
            st.markdown(f"""
            <div class="metric-card neutral">
              <div class="metric-value">{val}</div>
              <div class="metric-label">{label} (Baseline)</div>
            </div>""", unsafe_allow_html=True)

    # Visual comparison
    st.markdown('<div class="section-header">📊 Performance Comparison</div>', unsafe_allow_html=True)

    categories = ['Precision','Recall','F1 Score']
    naive_vals  = [metrics['naive_precision'], metrics['naive_recall'], metrics['naive_f1']]
    model_vals  = [metrics['model_precision'], metrics['model_recall'], metrics['model_f1']]
    target_vals = [0.75, 0.70, 0.72]

    fig_radar = go.Figure()
    fig_radar.add_trace(go.Bar(name='Naive Baseline', x=categories, y=[v*100 for v in naive_vals],
                               marker_color='#8b949e', opacity=0.7))
    fig_radar.add_trace(go.Bar(name='SentinelAI Model', x=categories, y=[v*100 for v in model_vals],
                               marker_color='#388bfd'))
    fig_radar.add_trace(go.Scatter(name='Target Threshold', x=categories, y=[v*100 for v in target_vals],
                                   mode='markers+lines',
                                   marker=dict(color='#3fb950', size=10, symbol='diamond'),
                                   line=dict(color='#3fb950', dash='dash', width=2)))
    fig_radar.update_layout(
        barmode='group',
        paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
        xaxis=dict(color='#8b949e', tickfont=dict(family='JetBrains Mono',size=12)),
        yaxis=dict(color='#8b949e', gridcolor='#1c2333', range=[0,110],
                   tickfont=dict(family='JetBrains Mono',size=10),
                   title=dict(text='Score (%)',font=dict(color='#8b949e'))),
        legend=dict(font=dict(color='#8b949e'), bgcolor='#0d1117'),
        margin=dict(t=20,b=20,l=20,r=20), height=350,
    )
    st.plotly_chart(fig_radar, use_container_width=True)

    # Model stats
    st.markdown('<div class="section-header">📈 Detection Statistics</div>', unsafe_allow_html=True)
    col3, col4, col5, col6 = st.columns(4)
    stats = [
        (col3, "Total Events", f"{metrics['total_events']:,}", "neutral"),
        (col4, "True Anomalies (GT)", f"{metrics['total_anomalies']:,}", "medium"),
        (col5, "ML Flagged", f"{metrics['ml_anomalies']:,}", "medium"),
        (col6, "Unauthorized Access", f"{metrics['unauth_count']:,}", "high"),
    ]
    for col, label, val, cls in stats:
        with col:
            st.markdown(f"""
            <div class="metric-card {cls}">
              <div class="metric-value">{val}</div>
              <div class="metric-label">{label}</div>
            </div>""", unsafe_allow_html=True)

    # False positive analysis
    st.markdown('<div class="section-header">🔍 False Positive Analysis — How We Control Alert Fatigue</div>', unsafe_allow_html=True)
    fp_points = [
        ("Month-end seasonality", "Finance team bulk access in last 3 days of month is deprioritised — time_classification context applied"),
        ("New admin access", "Role-change buffer: admin users accessing new resources in first 30 days get reduced unauthorized penalty"),
        ("Contractor patterns", "Service accounts flagged separately from user accounts — different baseline thresholds"),
        ("Legitimate bulk exports", "Data warehouse/BI tool exports scored with lower weight than customer vault exports"),
        ("On-call off-hours access", "IT/Security users accessing SIEM or Admin_Console off-hours get partial exemption via department mapping"),
        ("Failed login attempts", "Single failed logins score +10 only; repeated failures from same IP in same session scored cumulatively"),
    ]
    for title, desc in fp_points:
        st.markdown(f"""
        <div style="background:#0d1117;border:1px solid #1c2333;border-left:4px solid #388bfd;
             border-radius:6px;padding:14px 18px;margin-bottom:10px;">
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:#388bfd;
               font-weight:600;margin-bottom:4px;">{title}</div>
          <div style="font-size:0.8rem;color:#8b949e;">{desc}</div>
        </div>""", unsafe_allow_html=True)

    # Regulatory compliance
    st.markdown('<div class="section-header">⚖ Regulatory Compliance Coverage</div>', unsafe_allow_html=True)
    regs = [
        ("GDPR Article 32", "Personal data access monitoring — Customer_Vault and HRIS events tracked with full audit trail", "#f85149"),
        ("SOX 302", "GL_System and PROD_DB unauthorized access triggers immediate escalation with financial impact assessment", "#e3b341"),
        ("NIST IR-4", "Detection → alert → investigation workflow with structured incident response recommendations", "#388bfd"),
    ]
    for reg, desc, color in regs:
        st.markdown(f"""
        <div style="background:#0d1117;border:1px solid #1c2333;border-left:4px solid {color};
             border-radius:6px;padding:14px 18px;margin-bottom:10px;">
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:{color};
               font-weight:600;margin-bottom:4px;">{reg}</div>
          <div style="font-size:0.8rem;color:#8b949e;">{desc}</div>
        </div>""", unsafe_allow_html=True)
