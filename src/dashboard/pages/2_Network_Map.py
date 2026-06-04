import streamlit as st
from pyvis.network import Network
import tempfile
import pandas as pd
from src.dashboard.utils.data_loader import load_devices
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_legend_item, render_footer,
    COLORS
)

st.set_page_config(page_title="Mapa de Red - IPS/IDS", page_icon="🗺️", layout="wide")
inject_global_css()

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="🗺️",
    title="Topología de Red Interactiva",
    subtitle="Visualización del perímetro de red local mediante grafos físicos. Pase el ratón sobre los nodos para obtener trazabilidad forense.",
    gradient="linear-gradient(135deg, rgba(76, 201, 240, 0.1) 0%, rgba(15, 23, 42, 0.95) 60%, rgba(124, 58, 237, 0.08) 100%)",
    accent="linear-gradient(90deg, var(--accent-blue), var(--accent-purple))"
)

# Colores del mapa alineados con el sistema de diseño
MAP_COLORS = {
    "gateway": COLORS["accent_blue"],
    "low": "#22c55e",       # Verde
    "medium": COLORS["accent_amber"],
    "high": COLORS["accent_red"],
    "critical": COLORS["accent_red"],
    "offline": "#475569",
    "edge": "rgba(76, 201, 240, 0.4)",
    "edge_off": "rgba(71, 85, 105, 0.3)",
}

# ── Cargar dispositivos ────────────────────────────────────────
devices_df = load_devices()

if devices_df.empty:
    st.markdown(f"""
    <div style="
        text-align: center; padding: 60px 40px;
        background: rgba(76, 201, 240, 0.05);
        border: 1px solid rgba(76, 201, 240, 0.15);
        border-radius: 16px;
    ">
        <div style="font-size: 3rem; margin-bottom: 12px; animation: sentinel-float 3s ease-in-out infinite; display: inline-block;">📡</div>
        <div style="color: var(--accent-blue); font-weight: 600; font-size: 1.1rem;">Inicializando radares...</div>
        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 6px;">No hay dispositivos descubiertos por el crawler todavía</div>
    </div>
    """, unsafe_allow_html=True)
else:
    # ── KPIs de Red ─────────────────────────────────────────────
    total = len(devices_df)
    online = len(devices_df[devices_df['is_online'] == 1])
    at_risk = len(devices_df[devices_df['risk_level'].isin(['medium', 'high', 'critical'])])
    offline = total - online

    col_k1, col_k2, col_k3, col_k4 = st.columns(4)
    with col_k1:
        render_metric_card("📡", "Nodos Totales", str(total), accent="blue")
    with col_k2:
        render_metric_card("📶", "En Línea", str(online), accent="green", subtitle=f"{offline} dormidos")
    with col_k3:
        render_metric_card("⚠️", "En Riesgo", str(at_risk), accent="amber" if at_risk > 0 else "green", glow=at_risk > 0)
    with col_k4:
        health_pct = round((1 - at_risk / max(total, 1)) * 100)
        render_metric_card("💚", "Salud de Red", f"{health_pct}%", accent="cyan")

    render_section_divider("Grafo de Topología")

    col_map, col_legend = st.columns([5, 1])

    with col_legend:
        st.markdown("#### 🔑 Leyenda")
        st.markdown(render_legend_item(MAP_COLORS["gateway"], "Gateway Core"), unsafe_allow_html=True)
        st.markdown(render_legend_item(MAP_COLORS["low"], "Nodo Limpio"), unsafe_allow_html=True)
        st.markdown(render_legend_item(MAP_COLORS["medium"], "Riesgo Medio"), unsafe_allow_html=True)
        st.markdown(render_legend_item(MAP_COLORS["critical"], "Riesgo Crítico"), unsafe_allow_html=True)
        st.markdown(render_legend_item(MAP_COLORS["offline"], "Desconectado"), unsafe_allow_html=True)

    with col_map:
        # Crear red pyvis con fondo del sistema de diseño
        net = Network(height="650px", width="100%", bgcolor=COLORS["bg_deep"], font_color=COLORS["text_primary"])
        net.barnes_hut(gravity=-8000, spring_length=200)

        # Nodo central (Gateway)
        net.add_node("gateway", label="🌐\nCore Gateway", shape="hexagon", color=MAP_COLORS["gateway"], size=50)

        # Dispositivos periféricos
        for _, row in devices_df.iterrows():
            mac = row.get("mac", "unknown")
            ip = row.get("ip", "unknown")
            vendor = row.get("vendor", "Unknown")
            risk = row.get("risk_level", "low")
            online_status = row.get("is_online", 0)
            hostname = row.get("hostname")

            if not online_status:
                color = MAP_COLORS["offline"]
            else:
                color = MAP_COLORS.get(risk, MAP_COLORS["low"])

            display_name = hostname if hostname and hostname != "None" else vendor
            label = f"{display_name}\n{ip}"

            title = f"🔌 IP: {ip}\n📡 MAC: {mac}\n💻 SO: {row.get('os_guess', 'Desconocido')}\n⚠️ Riesgo: {risk.upper()}"

            net.add_node(mac, label=label, title=title, color=color, shape="dot", size=30)
            edge_color = MAP_COLORS["edge_off"] if not online_status else MAP_COLORS["edge"]
            net.add_edge("gateway", mac, color=edge_color, arrows="to")

        # Guardar como HTML y renderizar
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
            net.save_graph(tmp.name)
            with open(tmp.name, "r", encoding="utf-8") as f:
                html_data = f.read()

        import streamlit.components.v1 as components
        components.html(html_data, height=670)

render_footer()
