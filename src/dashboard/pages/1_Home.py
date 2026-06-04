import streamlit as st
import plotly.graph_objects as go
from src.dashboard.utils.data_loader import load_alert_summary, load_network_stats
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_status_badge, render_footer,
    get_plotly_layout, COLORS, SEVERITY_COLORS
)
from src.config import DASHBOARD_REFRESH_RATE
import time

st.set_page_config(page_title="Home - IPS/IDS", page_icon="🏠", layout="wide")
inject_global_css()

# Toggle de Auto-Refresco en el sidebar
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

# ── Header ──────────────────────────────────────────────────────
col_title, col_btn = st.columns([6, 1])
with col_title:
    render_page_header(
        icon="🏠",
        title="Dashboard Principal",
        subtitle="Visión panorámica del estado de la red y salud de la infraestructura en tiempo real.",
        gradient="linear-gradient(135deg, rgba(6, 214, 160, 0.1) 0%, rgba(15, 23, 42, 0.9) 50%, rgba(124, 58, 237, 0.1) 100%)",
        accent="linear-gradient(90deg, var(--accent-cyan), var(--accent-purple))"
    )
with col_btn:
    st.write("")
    st.write("")
    if st.button("🔄 Refrescar", use_container_width=True):
        st.rerun()

# ── Cargar datos ────────────────────────────────────────────────
summary = load_alert_summary()
stats_df = load_network_stats(limit=30)

total_alerts = summary.get("total", 0)
high_alerts = summary.get("by_severity", {}).get("high", 0) + summary.get("by_severity", {}).get("critical", 0)

# Determinar estado de la red
if high_alerts > 0:
    status_text = "Crítico"
    status_severity = "critical"
    status_accent = "red"
    status_glow = True
elif total_alerts > 0:
    status_text = "Advertencia"
    status_severity = "medium"
    status_accent = "amber"
    status_glow = True
else:
    status_text = "Saludable"
    status_severity = "ok"
    status_accent = "cyan"
    status_glow = False

current_bandwidth = 0.0
current_latency = 0.0
if not stats_df.empty:
    current_bandwidth = stats_df.iloc[-1]["bandwidth_mbps"]
    current_latency = stats_df.iloc[-1]["latency_ms"]

# ── KPI Cards ───────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

with col1:
    badge_html = render_status_badge(status_text, status_severity)
    st.markdown(f"""
    <div class="sentinel-metric accent-{status_accent} {"glow-active" if status_glow else ""}">
        <span class="metric-icon">🛡️</span>
        <span class="metric-label">Estado de la Red</span>
        <div style="margin-top: 10px;">{badge_html}</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    render_metric_card(
        icon="🚨",
        label="Alertas Activas",
        value=str(total_alerts),
        accent="red" if high_alerts > 0 else "green",
        subtitle=f"{high_alerts} críticas detectadas" if high_alerts > 0 else "Sin amenazas críticas",
        glow=high_alerts > 0
    )

with col3:
    render_metric_card(
        icon="📈",
        label="Ancho de Banda",
        value=f"{current_bandwidth:.2f} Mbps",
        accent="blue",
        subtitle="Tasa de transferencia actual"
    )

with col4:
    render_metric_card(
        icon="⚡",
        label="Latencia Media",
        value=f"{current_latency:.1f} ms",
        accent="purple",
        subtitle="Tiempo de respuesta al exterior"
    )

# ── Gráficos ────────────────────────────────────────────────────
render_section_divider("Análisis de Tendencias")

col_chart1, col_chart2 = st.columns([3, 2])

with col_chart1:
    st.markdown("#### 🌊 Tráfico de Red Reciente")
    if not stats_df.empty:
        fig_bw = go.Figure()
        fig_bw.add_trace(go.Scatter(
            x=stats_df["timestamp"], y=stats_df["bandwidth_mbps"],
            mode='lines',
            fill='tozeroy',
            line=dict(color=COLORS["accent_cyan"], width=2.5),
            fillcolor="rgba(6, 214, 160, 0.08)",
            name="Mbps",
            hovertemplate="<b>%{y:.2f} Mbps</b><br>%{x}<extra></extra>"
        ))
        layout = get_plotly_layout()
        layout["margin"] = dict(l=0, r=0, t=10, b=0)
        fig_bw.update_layout(**layout)
        st.plotly_chart(fig_bw, use_container_width=True)
    else:
        st.info("⏳ Esperando datos de red recientes para generar gráfica...")

with col_chart2:
    st.markdown("#### 🧬 Distribución de Amenazas")
    by_type = summary.get("by_type", {})
    if by_type:
        colors_seq = [COLORS["accent_cyan"], COLORS["accent_purple"], COLORS["accent_amber"],
                      COLORS["accent_red"], COLORS["accent_blue"], COLORS["accent_rose"]]
        fig_types = go.Figure(data=[go.Pie(
            labels=list(by_type.keys()),
            values=list(by_type.values()),
            hole=0.55,
            marker=dict(colors=colors_seq[:len(by_type)],
                        line=dict(color=COLORS["bg_deep"], width=2)),
            textinfo='percent+label',
            textposition='inside',
            textfont=dict(family="Inter", size=11, color="white"),
            hovertemplate="<b>%{label}</b><br>%{value} eventos (%{percent})<extra></extra>"
        )])
        layout = get_plotly_layout()
        layout["margin"] = dict(l=0, r=0, t=10, b=0)
        layout["showlegend"] = False
        fig_types.update_layout(**layout)
        st.plotly_chart(fig_types, use_container_width=True)
    else:
        st.markdown(f"""
        <div style="
            text-align: center; padding: 40px;
            background: rgba(6, 214, 160, 0.05);
            border: 1px solid rgba(6, 214, 160, 0.15);
            border-radius: 12px;
        ">
            <div style="font-size: 2.5rem; margin-bottom: 8px;">🎉</div>
            <div style="color: var(--accent-cyan); font-weight: 600;">No hay amenazas registradas</div>
            <div style="color: var(--text-muted); font-size: 0.85rem; margin-top: 4px;">El perímetro de red está limpio</div>
        </div>
        """, unsafe_allow_html=True)

render_footer()

# ── Auto-Refresh ────────────────────────────────────────────────
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
