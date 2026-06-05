import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta

from src.dashboard.utils.data_loader import (
    load_alerts, load_alert_summary, load_network_stats,
    load_active_device_count, load_avg_inference_latency,
)
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_status_badge, render_footer,
    get_plotly_layout, COLORS, SEVERITY_COLORS,
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
    if st.button("🔄 Refrescar", width="stretch"):
        st.rerun()

# ── Cargar datos ────────────────────────────────────────────────
# Consulta 1: alerts — conteo 24h, tabla recientes, estado global
now = datetime.now()
since_24h = (now - timedelta(hours=24)).isoformat()
since_6h = (now - timedelta(hours=6)).isoformat()
since_15m = (now - timedelta(minutes=15)).isoformat()

alerts_24h_df = load_alerts(limit=10000, since=since_24h)
total_alerts_24h = len(alerts_24h_df)

# Alertas recientes (5 más recientes)
recent_alerts_df = alerts_24h_df.head(5) if not alerts_24h_df.empty else alerts_24h_df

# Alertas para el gráfico temporal (últimas 6 horas)
alerts_6h_df = load_alerts(limit=50000, since=since_6h)

# Alertas críticas en los últimos 15 minutos (para semáforo)
alerts_15m_df = load_alerts(limit=10000, since=since_15m)
critical_15m = len(alerts_15m_df[alerts_15m_df["severity"].isin(["critical", "high"])]) if not alerts_15m_df.empty else 0

# Consulta 2: network_metrics — ancho de banda
stats_df = load_network_stats(limit=30)
current_bandwidth = 0.0
if not stats_df.empty:
    current_bandwidth = stats_df.iloc[-1]["bandwidth_mbps"]

# Consulta 3: devices — conteo de dispositivos activos
active_devices = load_active_device_count()

# Latencia media de inferencia (desde tabla alerts)
avg_inference_ms = load_avg_inference_latency(hours=24)

# Determinar estado de la red basado en dispositivos
if active_devices > 0:
    net_status_text = "En línea"
    net_status_severity = "ok"
    net_status_accent = "cyan"
    net_status_glow = False
else:
    net_status_text = "Sin dispositivos"
    net_status_severity = "medium"
    net_status_accent = "amber"
    net_status_glow = True

# ═══════════════════════════════════════════════════════════════
# BANDA 1: Tarjetas KPI
# ═══════════════════════════════════════════════════════════════
col1, col2, col3, col4 = st.columns(4)

with col1:
    badge_html = render_status_badge(net_status_text, net_status_severity)
    st.html(f"""
    <div class="sentinel-metric accent-{net_status_accent} {"glow-active" if net_status_glow else ""}">
        <span class="metric-icon">🛡️</span>
        <span class="metric-label">Estado de la Red</span>
        <div style="margin-top: 10px;">{badge_html}</div>
        <span class="metric-sub">{active_devices} dispositivos activos</span>
    </div>
    """)

with col2:
    high_alerts_24h = len(alerts_24h_df[alerts_24h_df["severity"].isin(["critical", "high"])]) if not alerts_24h_df.empty else 0
    render_metric_card(
        icon="🚨",
        label="Alertas (24h)",
        value=str(total_alerts_24h),
        accent="red" if high_alerts_24h > 0 else "green",
        subtitle=f"{high_alerts_24h} críticas detectadas" if high_alerts_24h > 0 else "Sin amenazas críticas",
        glow=high_alerts_24h > 0
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
        label="Latencia Inferencia",
        value=f"{avg_inference_ms:.1f} ms",
        accent="purple",
        subtitle="Media de inferencia ML (24h)"
    )

# ═══════════════════════════════════════════════════════════════
# BANDA 2: Gráfico temporal de alertas + Tabla de alertas recientes
# ═══════════════════════════════════════════════════════════════
render_section_divider("Actividad de Alertas")

# ── Gráfico de línea temporal: alertas por tipo cada 5 min ──
st.markdown("#### 🌊 Volumen de Alertas por Tipo de Ataque (últimas 6h)")

if not alerts_6h_df.empty:
    # Agrupar por intervalos de 5 minutos y tipo de ataque
    alerts_6h_df = alerts_6h_df.copy()
    alerts_6h_df["interval"] = alerts_6h_df["timestamp"].dt.floor("5min")

    attack_types = alerts_6h_df["attack_type"].unique()
    color_palette = [
        COLORS["accent_cyan"], COLORS["accent_purple"], COLORS["accent_amber"],
        COLORS["accent_red"], COLORS["accent_blue"], COLORS["accent_rose"],
        "#22c55e", "#e879f9", "#fbbf24", "#38bdf8",
    ]

    fig_timeline = go.Figure()
    for i, attack in enumerate(attack_types):
        subset = alerts_6h_df[alerts_6h_df["attack_type"] == attack]
        grouped = subset.groupby("interval").size().reset_index(name="count")
        color = color_palette[i % len(color_palette)]
        fig_timeline.add_trace(go.Scatter(
            x=grouped["interval"],
            y=grouped["count"],
            mode="lines+markers",
            name=attack,
            line=dict(color=color, width=2),
            marker=dict(size=4),
            hovertemplate=f"<b>{attack}</b><br>%{{x}}<br>%{{y}} alertas<extra></extra>",
        ))

    layout = get_plotly_layout()
    layout["margin"] = dict(l=0, r=0, t=10, b=0)
    layout["xaxis"]["title"] = "Tiempo"
    layout["yaxis"]["title"] = "Nº Alertas"
    layout["showlegend"] = True
    layout["legend"] = dict(
        bgcolor="rgba(0,0,0,0)",
        font=dict(color="#94a3b8", size=11),
        orientation="h",
        yanchor="bottom", y=1.02,
        xanchor="center", x=0.5,
    )
    fig_timeline.update_layout(**layout)
    st.plotly_chart(fig_timeline, width="stretch")
else:
    st.info("⏳ No hay alertas en las últimas 6 horas para generar gráfica temporal.")

# ── Tabla de las 5 alertas más recientes ──
st.markdown("#### 📋 Alertas Más Recientes")

if not recent_alerts_df.empty:
    display_df = recent_alerts_df[["timestamp", "src_ip", "dst_ip", "attack_type", "severity"]].copy()
    display_df.columns = ["Timestamp", "IP Origen", "IP Destino", "Tipo de Ataque", "Severidad"]
    display_df["Timestamp"] = display_df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    # Renderizar tabla con colores de severidad
    severity_map = {
        "critical": ("🔴", "#ef4444", "rgba(239, 68, 68, 0.15)"),
        "high":     ("🟠", "#f97316", "rgba(249, 115, 22, 0.15)"),
        "medium":   ("🟡", "#f59e0b", "rgba(245, 158, 11, 0.15)"),
        "low":      ("🟢", "#06d6a0", "rgba(6, 214, 160, 0.15)"),
        "info":     ("🔵", "#4cc9f0", "rgba(76, 201, 240, 0.15)"),
    }

    table_rows = ""
    for _, row in display_df.iterrows():
        sev_key = row["Severidad"].lower() if isinstance(row["Severidad"], str) else "info"
        dot, color, bg = severity_map.get(sev_key, ("⚪", "#94a3b8", "rgba(148,163,184,0.15)"))
        sev_label = row["Severidad"].capitalize() if isinstance(row["Severidad"], str) else "Info"
        table_rows += f"""
        <tr>
            <td style="padding: 10px 14px; border-bottom: 1px solid rgba(148,163,184,0.08); color: var(--text-muted); font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;">{row["Timestamp"]}</td>
            <td style="padding: 10px 14px; border-bottom: 1px solid rgba(148,163,184,0.08); color: var(--text-primary); font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">{row["IP Origen"] or "—"}</td>
            <td style="padding: 10px 14px; border-bottom: 1px solid rgba(148,163,184,0.08); color: var(--text-primary); font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">{row["IP Destino"] or "—"}</td>
            <td style="padding: 10px 14px; border-bottom: 1px solid rgba(148,163,184,0.08); color: var(--text-primary); font-weight: 500;">{row["Tipo de Ataque"]}</td>
            <td style="padding: 10px 14px; border-bottom: 1px solid rgba(148,163,184,0.08);">
                <span style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 100px; background: {bg}; color: {color}; font-weight: 600; font-size: 0.8rem;">
                    {dot} {sev_label}
                </span>
            </td>
        </tr>
        """

    st.html(f"""
    <div style="overflow-x: auto; border-radius: 12px; border: 1px solid rgba(148,163,184,0.12); background: rgba(15, 23, 42, 0.65); backdrop-filter: blur(16px);">
        <table style="width: 100%; border-collapse: collapse;">
            <thead>
                <tr style="border-bottom: 2px solid rgba(148,163,184,0.15);">
                    <th style="padding: 12px 14px; text-align: left; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 600;">Timestamp</th>
                    <th style="padding: 12px 14px; text-align: left; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 600;">IP Origen</th>
                    <th style="padding: 12px 14px; text-align: left; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 600;">IP Destino</th>
                    <th style="padding: 12px 14px; text-align: left; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 600;">Tipo de Ataque</th>
                    <th style="padding: 12px 14px; text-align: left; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 600;">Severidad</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>
    """)
else:
    st.html("""
    <div style="
        text-align: center; padding: 40px;
        background: rgba(6, 214, 160, 0.05);
        border: 1px solid rgba(6, 214, 160, 0.15);
        border-radius: 12px;
    ">
        <div style="font-size: 2.5rem; margin-bottom: 8px;">🎉</div>
        <div style="color: var(--accent-cyan); font-weight: 600;">No hay alertas recientes</div>
        <div style="color: var(--text-muted); font-size: 0.85rem; margin-top: 4px;">El perímetro de red está limpio</div>
    </div>
    """)

# ═══════════════════════════════════════════════════════════════
# BANDA 3: Semáforo de estado global del sistema
# ═══════════════════════════════════════════════════════════════
render_section_divider("Estado Global del Sistema")

# Lógica del semáforo basada en alertas críticas activas en los últimos 15 min:
#   0 alertas críticas  → SEGURO
#   1-3                 → ALERTA
#   > 3                 → CRÍTICO
if critical_15m == 0:
    sem_state = "SEGURO"
    sem_color = "#22c55e"
    sem_bg = "rgba(34, 197, 94, 0.12)"
    sem_border = "rgba(34, 197, 94, 0.3)"
    sem_icon = "🟢"
    sem_glow = f"0 0 30px rgba(34, 197, 94, 0.3)"
    sem_description = "No se han detectado alertas críticas en los últimos 15 minutos."
elif critical_15m <= 3:
    sem_state = "ALERTA"
    sem_color = "#f59e0b"
    sem_bg = "rgba(245, 158, 11, 0.12)"
    sem_border = "rgba(245, 158, 11, 0.3)"
    sem_icon = "🟡"
    sem_glow = f"0 0 30px rgba(245, 158, 11, 0.3)"
    sem_description = f"{critical_15m} alerta(s) crítica(s) detectada(s) en los últimos 15 minutos."
else:
    sem_state = "CRÍTICO"
    sem_color = "#ef4444"
    sem_bg = "rgba(239, 68, 68, 0.15)"
    sem_border = "rgba(239, 68, 68, 0.4)"
    sem_icon = "🔴"
    sem_glow = f"0 0 40px rgba(239, 68, 68, 0.4), 0 0 80px rgba(239, 68, 68, 0.2)"
    sem_description = f"¡{critical_15m} alertas críticas activas! Se requiere acción inmediata."

st.html(f"""
<div style="
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 32px;
    padding: 40px 48px;
    background: {sem_bg};
    border: 2px solid {sem_border};
    border-radius: 20px;
    box-shadow: {sem_glow};
    animation: sentinel-pulse 2.5s ease-in-out infinite;
    --glow-color: {sem_color};
    transition: all 0.3s ease;
">
    <!-- Indicador circular -->
    <div style="
        width: 100px;
        height: 100px;
        border-radius: 50%;
        background: radial-gradient(circle, {sem_color} 0%, rgba(0,0,0,0) 70%);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 3.5rem;
        flex-shrink: 0;
        box-shadow: 0 0 40px {sem_color}44, 0 0 80px {sem_color}22;
    ">
        {sem_icon}
    </div>

    <!-- Texto del estado -->
    <div style="text-align: left;">
        <div style="
            font-family: 'JetBrains Mono', monospace;
            font-size: 3rem;
            font-weight: 800;
            color: {sem_color};
            letter-spacing: 0.08em;
            line-height: 1.1;
            text-shadow: 0 0 20px {sem_color}44;
        ">
            {sem_state}
        </div>
        <div style="
            color: var(--text-muted);
            font-size: 1rem;
            margin-top: 8px;
            line-height: 1.4;
        ">
            {sem_description}
        </div>
        <div style="
            color: var(--text-muted);
            font-size: 0.78rem;
            margin-top: 6px;
            opacity: 0.6;
        ">
            Basado en alertas críticas de los últimos 15 minutos • Actualización cada {DASHBOARD_REFRESH_RATE}s
        </div>
    </div>
</div>
""")

render_footer()

# ── Auto-Refresh ────────────────────────────────────────────────
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
