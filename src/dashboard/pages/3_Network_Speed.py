import streamlit as st
import plotly.graph_objects as go
from src.dashboard.utils.data_loader import load_network_stats
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_footer, get_plotly_layout, COLORS
)

st.set_page_config(page_title="Rendimiento de Red - IPS/IDS", page_icon="⚡", layout="wide")
inject_global_css()

# ── Header ──────────────────────────────────────────────────────
col_title, col_btn = st.columns([5, 1])
with col_title:
    render_page_header(
        icon="⚡",
        title="Rendimiento y Telemetría",
        subtitle="Monitorización continua del tráfico RAW, ancho de banda saturado y estrés de la Raspberry Pi.",
        gradient="linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(15, 23, 42, 0.95) 50%, rgba(76, 201, 240, 0.08) 100%)",
        accent="linear-gradient(90deg, var(--accent-amber), var(--accent-cyan))"
    )
with col_btn:
    st.write("")
    if st.button("🔄 Refrescar", use_container_width=True):
        st.rerun()

# ── Filtros ─────────────────────────────────────────────────────
col_filtro, _ = st.columns([1, 3])
horas = col_filtro.selectbox(
    "🔎 Ventana Temporal:",
    [1, 3, 6, 12, 24],
    index=1,
    format_func=lambda x: f"Últimas {x} horas de captura"
)

stats_df = load_network_stats(limit=1000, hours=horas)

if stats_df.empty:
    st.markdown("""
    <div style="
        text-align: center; padding: 60px 40px;
        background: rgba(245, 158, 11, 0.05);
        border: 1px solid rgba(245, 158, 11, 0.15);
        border-radius: 16px;
    ">
        <div style="font-size: 3rem; margin-bottom: 12px; animation: sentinel-float 3s ease-in-out infinite; display: inline-block;">⏳</div>
        <div style="color: var(--accent-amber); font-weight: 600; font-size: 1.1rem;">Esperando datos del sniffer...</div>
        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 6px;">Refresca en un minuto para ver las primeras métricas</div>
    </div>
    """, unsafe_allow_html=True)
else:
    current = stats_df.iloc[-1]

    # ── Métricas Top ────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_metric_card("📡", "Tasa de Transferencia", f"{current['bandwidth_mbps']:.2f} Mbps", accent="amber")
    with col2:
        render_metric_card("🌍", "Latencia al Exterior", f"{current['latency_ms']:.1f} ms", accent="blue")
    with col3:
        cpu_val = current['cpu_percent']
        cpu_accent = "red" if cpu_val > 80 else ("amber" if cpu_val > 50 else "green")
        render_metric_card("🖥️", "CPU (Raspberry Pi)", f"{cpu_val}%", accent=cpu_accent, glow=cpu_val > 80)
    with col4:
        render_metric_card("🔗", "Sockets TCP/UDP", str(current['active_connections']), accent="purple")

    # ── Gráfico de Ancho de Banda ───────────────────────────────
    render_section_divider("Histograma de Ancho de Banda")

    fig_bw = go.Figure()
    fig_bw.add_trace(go.Scatter(
        x=stats_df["timestamp"], y=stats_df["bandwidth_mbps"],
        mode='lines',
        fill='tozeroy',
        line=dict(color=COLORS["accent_purple"], width=2.5),
        fillcolor="rgba(124, 58, 237, 0.08)",
        name="Mbps",
        hovertemplate="<b>%{y:.2f} Mbps</b><br>%{x}<extra></extra>"
    ))
    layout = get_plotly_layout()
    layout["margin"] = dict(l=0, r=0, t=10, b=0)
    fig_bw.update_layout(**layout)
    st.plotly_chart(fig_bw, use_container_width=True)

    # ── Gráficos de Hardware ────────────────────────────────────
    render_section_divider("Esfuerzo de Hardware Host")

    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        fig_cpu = go.Figure()
        fig_cpu.add_trace(go.Scatter(
            x=stats_df["timestamp"], y=stats_df["cpu_percent"],
            mode='lines',
            line=dict(color=COLORS["accent_amber"], width=2),
            fill='tozeroy',
            fillcolor="rgba(245, 158, 11, 0.06)",
            name="CPU %",
            hovertemplate="<b>CPU: %{y:.1f}%</b><br>%{x}<extra></extra>"
        ))
        layout = get_plotly_layout()
        layout["title"] = dict(text="Consumo de CPU (%)", font=dict(color=COLORS["text_muted"], size=14))
        fig_cpu.update_layout(**layout)
        st.plotly_chart(fig_cpu, use_container_width=True)

    with col_chart2:
        fig_mem = go.Figure()
        fig_mem.add_trace(go.Scatter(
            x=stats_df["timestamp"], y=stats_df["memory_percent"],
            mode='lines',
            line=dict(color="#22c55e", width=2),
            fill='tozeroy',
            fillcolor="rgba(34, 197, 94, 0.06)",
            name="RAM %",
            hovertemplate="<b>RAM: %{y:.1f}%</b><br>%{x}<extra></extra>"
        ))
        layout = get_plotly_layout()
        layout["title"] = dict(text="Consumo de Memoria RAM (%)", font=dict(color=COLORS["text_muted"], size=14))
        fig_mem.update_layout(**layout)
        st.plotly_chart(fig_mem, use_container_width=True)

render_footer()
