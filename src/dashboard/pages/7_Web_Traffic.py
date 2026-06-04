import streamlit as st
import pandas as pd
import time
from src.dashboard.utils.data_loader import load_web_traffic, load_devices
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_status_badge, render_footer, COLORS
)
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Tráfico Web (DPI) - IPS/IDS", page_icon="🌐", layout="wide")
inject_global_css()

# Toggle de Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="🌐",
    title="Auditoría de Navegación y Deep Packet Inspection",
    subtitle="Inspección de tráfico de capa de Aplicación (Capa 7 OSI) capturado mediante SNI e interrogatorios DNS nativos.",
    gradient="linear-gradient(135deg, rgba(27, 38, 59, 0.8) 0%, rgba(13, 27, 42, 0.95) 100%)",
    accent="linear-gradient(90deg, var(--accent-blue), var(--accent-cyan))"
)

# ── Estado de streaming ─────────────────────────────────────────
col_status, _ = st.columns([8, 2])
with _:
    if auto_refresh:
        st.markdown(render_status_badge("Streaming Activo", "ok"), unsafe_allow_html=True)
    else:
        st.markdown(render_status_badge("Modo Histórico", "medium"), unsafe_allow_html=True)

# ── Filtros ─────────────────────────────────────────────────────
devices_df = load_devices()
device_ips = ["Todas las IPs"]
if not devices_df.empty:
    device_ips.extend(devices_df["ip"].dropna().unique().tolist())

col_f1, col_f2 = st.columns(2)
with col_f1:
    selected_ip = st.selectbox("📍 Rastrear nodo concreto (IP Origen):", device_ips)

with col_f2:
    search_query = st.text_input("🔍 Buscar término, app o protocolo (ej: whatsapp, netflix, DNS):", "")

render_section_divider("Registro de Intercepciones")

# ── Cargar datos ────────────────────────────────────────────────
with st.spinner("Decodificando buffers de tráfico..."):
    df = load_web_traffic(limit=1000)

if df.empty:
    st.markdown("""
    <div style="
        text-align: center; padding: 60px 40px;
        background: rgba(76, 201, 240, 0.05);
        border: 1px solid rgba(76, 201, 240, 0.15);
        border-radius: 16px;
    ">
        <div style="font-size: 3rem; margin-bottom: 12px; animation: sentinel-float 3s ease-in-out infinite; display: inline-block;">🔎</div>
        <div style="color: var(--accent-blue); font-weight: 600; font-size: 1.1rem;">Sin intercepciones registradas</div>
        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 6px;">Aún no hay tráfico HTTP/S o DNS capturado en la base de datos</div>
    </div>
    """, unsafe_allow_html=True)
else:
    # Aplicar filtros
    if selected_ip != "Todas las IPs":
        df = df[df["src_ip"] == selected_ip]

    if search_query:
        mask = (
            df["domain_url"].str.contains(search_query, case=False, na=False) |
            df["protocol"].str.contains(search_query, case=False, na=False)
        )
        df = df[mask]

    if df.empty:
        st.warning("No hay registros que coincidan con los filtros de búsqueda.")
    else:
        # Colores de protocolo del sistema de diseño
        PROTOCOL_COLORS = {
            "DNS": COLORS["accent_blue"],
            "HTTPS": "#22c55e",
            "HTTP": COLORS["accent_amber"],
            "FTP": COLORS["accent_red"],
            "SMTP": COLORS["accent_purple"],
        }

        def color_protocol(val):
            color = PROTOCOL_COLORS.get(val, "")
            if color:
                return f"color: {color}; font-weight: bold;"
            return ""

        display_df = df[["timestamp", "src_ip", "dst_ip", "protocol", "domain_url"]].copy()
        display_df.rename(columns={
            "timestamp": "Hora",
            "src_ip": "Origen",
            "dst_ip": "Destino",
            "protocol": "Protocolo",
            "domain_url": "Dominio Resoluto / Petición"
        }, inplace=True)

        display_df = display_df.sort_values(by="Hora", ascending=False)

        st.dataframe(
            display_df.style.map(color_protocol, subset=['Protocolo']),
            use_container_width=True,
            hide_index=True,
            height=600
        )

        st.caption(f"Visualizando spool temporal: **{len(display_df)} tramas extraídas**.")

    # ── Métricas de inteligencia ────────────────────────────────
    if not df.empty:
        render_section_divider("Inteligencia de Navegación Extraída")

        m1, m2, m3 = st.columns(3)

        with m1:
            render_metric_card("📊", "Total Intercepciones", str(len(df)), accent="blue")

        with m2:
            top_protocol = df["protocol"].value_counts().index[0] if not df["protocol"].empty else "N/A"
            render_metric_card("📡", "Protocolo Dominante", top_protocol, accent="cyan")

        with m3:
            top_domain = "N/A"
            if "DNS" in df["protocol"].values or "HTTPS" in df["protocol"].values:
                domains = df[df["protocol"].isin(["DNS", "HTTPS"])]["domain_url"]
                if not domains.empty:
                    top_domain = domains.value_counts().index[0]
                    if len(top_domain) > 30:
                        top_domain = top_domain[:27] + "..."
            render_metric_card("🌍", "Top Destino Mundial", top_domain, accent="purple")

render_footer()

# ── Auto-Refresh ────────────────────────────────────────────────
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
