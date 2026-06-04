import streamlit as st
from src.dashboard.utils.styles import inject_global_css, render_footer

st.set_page_config(
    page_title="Edge-IIoTset IPS/IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_global_css()

# ── Hero Panel ──────────────────────────────────────────────────
st.markdown("""
<div style="
    background: linear-gradient(135deg, rgba(124, 58, 237, 0.15) 0%, rgba(6, 214, 160, 0.08) 50%, rgba(76, 201, 240, 0.1) 100%);
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 24px;
    padding: 48px 40px 40px 40px;
    text-align: center;
    position: relative;
    overflow: hidden;
    margin-bottom: 36px;
">
    <div style="
        font-size: 4.5rem;
        margin-bottom: 12px;
        animation: sentinel-float 3s ease-in-out infinite;
        display: inline-block;
    ">🛡️</div>
    <h1 style="
        font-size: 2.6rem !important;
        margin: 0 0 10px 0 !important;
        background: linear-gradient(135deg, #f1f5f9 0%, #4cc9f0 50%, #06d6a0 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        letter-spacing: -0.03em;
    ">Edge-IIoTset: IPS/IDS</h1>
    <p style="
        color: #94a3b8;
        font-size: 1.15rem;
        max-width: 600px;
        margin: 0 auto 8px auto;
        line-height: 1.6;
    ">Sistema de Prevención y Detección de Intrusiones con Inteligencia Artificial para redes IoT</p>
    <div style="
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, var(--accent-purple), var(--accent-cyan), var(--accent-cyan), var(--accent-purple), transparent);
    "></div>
</div>
""", unsafe_allow_html=True)

# ── Navegación Visual ───────────────────────────────────────────
st.markdown("""
<div style="
    color: var(--text-muted);
    text-align: center;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    font-weight: 600;
    margin-bottom: 20px;
">👈 Selecciona una vista en el menú lateral para comenzar</div>
""", unsafe_allow_html=True)

nav_items = [
    ("🏠", "Home", "Resumen global, KPIs y estado de salud de la red en tiempo real", "var(--accent-cyan)"),
    ("🗺️", "Mapa de Red", "Topología interactiva de dispositivos y conexiones", "var(--accent-blue)"),
    ("⚡", "Rendimiento", "Ancho de banda, latencia y métricas de hardware del host", "var(--accent-amber)"),
    ("🚨", "Alertas SOC", "Registro de amenazas detectadas por IA y auditorías de firmware", "var(--accent-red)"),
    ("📱", "Dispositivos", "Inventario completo de hardware con escaneo Nmap", "var(--accent-purple)"),
    ("⚙️", "Configuración", "Base de datos, modelo ML y módulo ofensivo MITM", "#94a3b8"),
    ("🌐", "Tráfico Web", "Deep Packet Inspection de capa 7 — SNI y DNS", "var(--accent-blue)"),
]

# Build the cards grid in HTML
cards_html = ""
for icon, title, desc, accent in nav_items:
    cards_html += f"""
    <div class="sentinel-nav-card" style="--card-accent: {accent};">
        <span class="nav-icon">{icon}</span>
        <div class="nav-title">{title}</div>
        <div class="nav-desc">{desc}</div>
    </div>
    """

st.markdown(f"""
<div style="
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
">
    {cards_html}
</div>
""", unsafe_allow_html=True)

render_footer()
