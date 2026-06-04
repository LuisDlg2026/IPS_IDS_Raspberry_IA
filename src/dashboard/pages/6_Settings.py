import streamlit as st
import os
from src.dashboard.utils.data_loader import get_db

st.set_page_config(page_title="Configuración - IPS/IDS", page_icon="⚙️", layout="wide")

# -- CSS Personalizado --
st.markdown("""
<style>
    .card-settings {
        background-color: #1A1A1A;
        border-radius: 12px;
        padding: 20px;
        border: 1px solid #333;
        box-shadow: 0 4px 6px rgba(0,0,0,0.4);
    }
    .db-metric {
        background-color: #2D2D2D;
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        border-bottom: 3px solid #00b4d8;
    }
</style>
""", unsafe_allow_html=True)

st.title("⚙️ Configuración y Mantenimiento")
st.markdown("Panel de control para la base de datos, modelos de IA y herramientas ofensivas.")

st.write('<br>', unsafe_allow_html=True)
db = get_db()
stats = db.get_db_stats()

# --- BLOQUE 1: Base de Datos ---
st.markdown('<div class="card-settings">', unsafe_allow_html=True)
st.subheader("💾 Estado de la Base de Datos")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown('<div class="db-metric">', unsafe_allow_html=True)
    st.metric("Alertas Históricas", stats.get("alerts", 0))
    st.markdown('</div>', unsafe_allow_html=True)
with col2:
    st.markdown('<div class="db-metric">', unsafe_allow_html=True)
    st.metric("Dispositivos Cacheados", stats.get("devices", 0))
    st.markdown('</div>', unsafe_allow_html=True)
with col3:
    st.markdown('<div class="db-metric">', unsafe_allow_html=True)
    st.metric("Muestras de Rendimiento", stats.get("network_stats", 0))
    st.markdown('</div>', unsafe_allow_html=True)
with col4:
    st.markdown('<div class="db-metric">', unsafe_allow_html=True)
    st.metric("Peso en Disco (SQLite)", f"{stats.get('file_size_mb', 0)} MB")
    st.markdown('</div>', unsafe_allow_html=True)

st.write("<br>", unsafe_allow_html=True)
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
st.markdown('</div><br>', unsafe_allow_html=True)

# --- BLOQUE 2: Modelo ML ---
st.markdown('<div class="card-settings">', unsafe_allow_html=True)
col_ml1, col_ml2 = st.columns([1, 2])
with col_ml1:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/0/05/Scikit_learn_logo_small.svg/1200px-Scikit_learn_logo_small.svg.png", width=150)
with col_ml2:
    st.subheader("🧠 Configuración del Motor de Inferencia")
    st.info("Para forzar el uso de otro modelo entrenado (ej. CatBoost o LightGBM) modifica la variable de entorno `.env` O pásala en la consola `IDS_MODEL=lightgbm`.")
    current_model = os.environ.get("IDS_MODEL", "random_forest.yml / joblib")
    st.text_input("Modelo Cargado Actual (Memoria RAM):", value=current_model, disabled=True)
st.markdown('</div><br>', unsafe_allow_html=True)

# --- BLOQUE 3: Ataques MITM ---
st.markdown('<div class="card-settings" style="border-left: 5px solid #ff4b4b;">', unsafe_allow_html=True)
st.subheader("🕵️‍♂️ Módulo Ofensivo (MITM / ARP Spoofing)")
st.warning("⚠️ **ATENCIÓN:** Esta función engaña a la red para redirigir el tráfico del dispositivo objetivo a través de la Raspberry Pi. Si se interrumpe el script, el objetivo perderá la conexión a Internet temporalmente.")

# Leer estado actual de la DB
mitm_enabled = db.get_setting("mitm_enabled") == "1"
current_target = db.get_setting("mitm_target_ip", "")

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
    st.error(f"☠️ **MODO ACTIVO DE COMBATE:** Interceptando tráfico RAW pasivamente de **{current_target}**")
st.markdown('</div>', unsafe_allow_html=True)
