import streamlit as st
import os
from src.dashboard.utils.data_loader import get_db

st.set_page_config(page_title="Configuración - IPS/IDS", page_icon="⚙️", layout="wide")

st.title("⚙️ Ajustes del Sistema")
st.markdown("Administra la base de datos y la configuración general del IDS/IPS.")

st.subheader("Base de Datos (SQLite)")

db = get_db()
stats = db.get_db_stats()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Alertas", stats.get("alerts", 0))
col2.metric("Dispositivos", stats.get("devices", 0))
col3.metric("Muestras de Red", stats.get("network_stats", 0))
col4.metric("Tamaño DB", f"{stats.get('file_size_mb', 0)} MB")

st.divider()

st.subheader("Mantenimiento")

if st.button("🧹 Limpiar registros antiguos (Más de 30 días)", type="primary"):
    db.cleanup(days=30)
    st.success("Limpieza completada exitosamente. Se ha ejecutado VACUUM en SQLite.")
    
st.divider()

st.subheader("Configuración del Modelo ML")
st.info("Para cambiar el modelo activo, modifica la variable de entorno `IDS_MODEL` antes de iniciar el backend.")

current_model = os.environ.get("IDS_MODEL", "random_forest")
st.text_input("Modelo Activo Actual", value=current_model, disabled=True)
