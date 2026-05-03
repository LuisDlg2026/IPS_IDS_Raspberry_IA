import streamlit as st

st.set_page_config(
    page_title="Edge-IIoTset IPS/IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🛡️ Edge-IIoTset: Sistema IPS/IDS")
st.markdown("### Bienvenido al Panel de Control de Seguridad")

st.info("👈 Selecciona una opción en el menú lateral para navegar por las diferentes vistas del sistema.")

st.markdown("""
Esta interfaz te permite monitorizar en tiempo real el tráfico de tu red IoT, visualizar alertas generadas por nuestro modelo de **Machine Learning**, descubrir dispositivos conectados y auditar su seguridad de firmware.

**Vistas disponibles:**
- 🏠 **Home**: Resumen global del estado de salud de la red y KPIs principales.
- 🌐 **Mapa de Red**: Topología gráfica de dispositivos y sus conexiones.
- ⚡ **Velocidad de Red**: Monitorización de ancho de banda y latencia.
- 🚨 **Alertas**: Registro histórico de amenazas detectadas y auditorías de firmware.
- 📱 **Dispositivos**: Inventario completo de hardware conectado.
""")
