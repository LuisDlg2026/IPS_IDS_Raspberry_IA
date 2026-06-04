import streamlit as st
import os
from src.dashboard.utils.data_loader import get_db
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_status_badge, render_footer, COLORS
)

st.set_page_config(page_title="Configuración - IPS/IDS", page_icon="⚙️", layout="wide")
inject_global_css()

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="⚙️",
    title="Configuración y Mantenimiento",
    subtitle="Panel de control para la base de datos, modelos de IA y herramientas ofensivas.",
    gradient="linear-gradient(135deg, rgba(148, 163, 184, 0.08) 0%, rgba(15, 23, 42, 0.95) 100%)",
    accent="linear-gradient(90deg, #64748b, var(--accent-blue))"
)

db = get_db()
stats = db.get_db_stats()

# ═══════════════════════════════════════════════════════════════
# BLOQUE 1: Base de Datos
# ═══════════════════════════════════════════════════════════════
render_section_divider("💾 Estado de la Base de Datos")

col1, col2, col3, col4 = st.columns(4)
with col1:
    render_metric_card("🚨", "Alertas Históricas", str(stats.get("alerts", 0)), accent="red")
with col2:
    render_metric_card("📱", "Dispositivos Cacheados", str(stats.get("devices", 0)), accent="blue")
with col3:
    render_metric_card("📊", "Muestras de Rendimiento", str(stats.get("network_stats", 0)), accent="purple")
with col4:
    render_metric_card("💾", "Peso en Disco", f"{stats.get('file_size_mb', 0)} MB", accent="cyan")

st.write("")
col_m1, col_m2 = st.columns(2)

with col_m1:
    if st.button("🧹 Purgar registros antiguos (> 30 días)", type="primary", use_container_width=True):
        db.cleanup(days=30)
        st.success("Limpieza completada exitosamente.")
        st.rerun()

with col_m2:
    if st.button("🚨 Reiniciar Base de Alertas RAW", type="secondary", use_container_width=True):
        db.clear_alerts()
        st.success("Todas las alertas han sido eliminadas.")
        st.rerun()

# ═══════════════════════════════════════════════════════════════
# BLOQUE 2: Modelo ML
# ═══════════════════════════════════════════════════════════════
render_section_divider("🧠 Motor de Inferencia ML")

st.markdown("""
<div class="glass-card" style="border-left: 3px solid var(--accent-purple);">
""", unsafe_allow_html=True)

col_ml1, col_ml2 = st.columns([1, 3])
with col_ml1:
    st.markdown("""
    <div style="
        text-align: center;
        padding: 20px;
        background: rgba(124, 58, 237, 0.08);
        border-radius: 12px;
        border: 1px solid rgba(124, 58, 237, 0.2);
    ">
        <div style="font-size: 3rem; animation: sentinel-float 3s ease-in-out infinite; display: inline-block;">🧠</div>
        <div style="color: var(--accent-purple); font-weight: 600; font-size: 0.85rem; margin-top: 8px;">ML ENGINE</div>
    </div>
    """, unsafe_allow_html=True)
with col_ml2:
    st.markdown("#### Configuración del Motor de Inferencia")
    st.info("Para forzar el uso de otro modelo entrenado (ej. CatBoost o LightGBM) modifica la variable de entorno `.env` O pásala en la consola `IDS_MODEL=lightgbm`.")
    current_model = os.environ.get("IDS_MODEL", "random_forest.yml / joblib")
    st.text_input("Modelo Cargado Actual (Memoria RAM):", value=current_model, disabled=True)

st.markdown('</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# BLOQUE 3: MITM / ARP Spoofing
# ═══════════════════════════════════════════════════════════════
render_section_divider("🕵️‍♂️ Módulo Ofensivo (MITM)")

# Leer estado actual
mitm_enabled = db.get_setting("mitm_enabled") == "1"
current_target = db.get_setting("mitm_target_ip", "")

# Contenedor con glow si activo
glow_style = "animation: sentinel-pulse 2.5s ease-in-out infinite; --glow-color: var(--accent-red);" if mitm_enabled else ""

st.markdown(f"""
<div class="glass-card" style="border-left: 3px solid var(--accent-red); {glow_style}">
""", unsafe_allow_html=True)

st.warning("⚠️ **ATENCIÓN:** Esta función engaña a la red para redirigir el tráfico del dispositivo objetivo a través de la Raspberry Pi. Si se interrumpe el script, el objetivo perderá la conexión a Internet temporalmente.")

devices = db.get_devices(online_only=True)
device_options = [""]
if devices:
    device_options.extend([d['ip'] for d in devices if d['ip'] != "192.168.1.1" and d['ip'] != "127.0.0.1"])

col_sp1, col_sp2 = st.columns([3, 1])

with col_sp1:
    try:
        default_idx = device_options.index(current_target) if current_target in device_options else 0
    except ValueError:
        default_idx = 0

    target_ip = st.selectbox(
        "🎯 Dispositivo Objetivo (Selecciona una IP descubierta):",
        options=device_options,
        index=default_idx,
        disabled=mitm_enabled
    )

with col_sp2:
    st.write("")
    st.write("")
    if not mitm_enabled:
        if st.button("🔥 Iniciar Intercepción", type="primary", use_container_width=True) and target_ip:
            db.set_setting("mitm_target_ip", target_ip)
            db.set_setting("mitm_enabled", "1")
            st.rerun()
    else:
        if st.button("⏹️ ABORTAR MITM", type="primary", use_container_width=True):
            db.set_setting("mitm_enabled", "0")
            st.rerun()

if mitm_enabled:
    st.markdown(f"""
    <div style="
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 12px;
        padding: 16px 20px;
        margin-top: 12px;
        display: flex;
        align-items: center;
        gap: 12px;
    ">
        <span style="font-size: 1.5rem; animation: sentinel-glow 1.5s ease-in-out infinite;">☠️</span>
        <div>
            <div style="color: var(--accent-red); font-weight: 700; font-size: 0.95rem;">MODO ACTIVO DE COMBATE</div>
            <div style="color: var(--text-muted); font-size: 0.85rem;">Interceptando tráfico RAW pasivamente de <strong style="color: var(--text-primary);">{current_target}</strong></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)

render_footer()
