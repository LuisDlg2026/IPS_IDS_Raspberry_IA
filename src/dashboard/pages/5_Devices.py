import streamlit as st
import time
import json
from src.dashboard.utils.data_loader import load_devices
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_footer, COLORS, SEVERITY_COLORS, SEVERITY_BG
)
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Inventario - IPS/IDS", page_icon="📱", layout="wide")
inject_global_css()

# Toggle de Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="📱",
    title="Directorio de Hosts y Dispositivos",
    subtitle="Auditoría pasiva y activa de todo el hardware detectado operando en tu red.",
    gradient="linear-gradient(135deg, rgba(76, 201, 240, 0.08) 0%, rgba(15, 23, 42, 0.95) 50%, rgba(124, 58, 237, 0.1) 100%)",
    accent="linear-gradient(90deg, var(--accent-blue), var(--accent-purple))"
)

# ── Filtros ─────────────────────────────────────────────────────
col_f1, col_f2 = st.columns([1, 4])
with col_f1:
    online_only = st.checkbox("🟢 Sólo dispositivos online", value=False)

devices_df = load_devices(online_only=online_only)

if devices_df.empty:
    st.markdown("""
    <div style="
        text-align: center; padding: 60px 40px;
        background: rgba(76, 201, 240, 0.05);
        border: 1px solid rgba(76, 201, 240, 0.15);
        border-radius: 16px;
    ">
        <div style="font-size: 3rem; margin-bottom: 12px; animation: sentinel-float 3s ease-in-out infinite; display: inline-block;">🔍</div>
        <div style="color: var(--accent-blue); font-weight: 600; font-size: 1.1rem;">Buscando dispositivos físicos...</div>
        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 6px;">Rastreando la capa de red para descubrir hardware</div>
    </div>
    """, unsafe_allow_html=True)
else:
    # ── Métricas rápidas ────────────────────────────────────────
    total = len(devices_df)
    online = len(devices_df[devices_df['is_online'] == 1])
    vuln = len(devices_df[devices_df['risk_level'].isin(['medium', 'high', 'critical'])])

    col1, col2, col3 = st.columns(3)
    with col1:
        render_metric_card("📡", "Total Histórico Descubiertos", str(total), accent="blue")
    with col2:
        render_metric_card("📶", "Conectados (Vivientes)", str(online), accent="green",
                          subtitle=f"{total - online} dormidos")
    with col3:
        render_metric_card("🔥", "Riesgo Medio/Alto", str(vuln), accent="red" if vuln > 0 else "green",
                          glow=vuln > 0)

    render_section_divider("Inventario Completo")

    # ── Formateo visual ─────────────────────────────────────────
    def color_risk(val):
        risk_styles = {
            'critical': f'background-color: {SEVERITY_BG["critical"]}; color: {SEVERITY_COLORS["critical"]}; border-left: 4px solid {SEVERITY_COLORS["critical"]}; font-weight: bold;',
            'high': f'background-color: {SEVERITY_BG["high"]}; color: {SEVERITY_COLORS["high"]}; border-left: 4px solid {SEVERITY_COLORS["high"]}; font-weight: bold;',
            'medium': f'background-color: {SEVERITY_BG["medium"]}; color: {SEVERITY_COLORS["medium"]}; border-left: 4px solid {SEVERITY_COLORS["medium"]}; font-weight: bold;',
            'low': f'background-color: {SEVERITY_BG["low"]}; color: {SEVERITY_COLORS["low"]}; border-left: 4px solid {SEVERITY_COLORS["low"]}; font-weight: bold;',
        }
        return risk_styles.get(val, 'color: white;')

    def format_online(val):
        return '🟢 Activo' if val == 1 else '💤 Dormido'

    display_df = devices_df.copy()
    display_df['is_online'] = display_df['is_online'].apply(format_online)

    def parse_ports(val):
        if not val: return []
        try: return json.loads(val)
        except: return []

    display_df['open_ports'] = display_df['open_ports'].apply(parse_ports)

    styled_df = display_df.style.map(color_risk, subset=['risk_level'])

    st.dataframe(
        styled_df,
        column_config={
            "mac": st.column_config.TextColumn("Dir. Física (MAC)"),
            "ip": st.column_config.TextColumn("Dir. Lógica (IP)"),
            "hostname": st.column_config.TextColumn("Alias / DNS"),
            "notes": st.column_config.TextColumn("📝 Tags"),
            "vendor": st.column_config.TextColumn("Hardware / OUI"),
            "os_guess": st.column_config.TextColumn("Kernel / SO"),
            "open_ports": st.column_config.ListColumn("Puertos (TCP)"),
            "risk_level": st.column_config.TextColumn("Nivel de Exposición"),
            "is_online": st.column_config.TextColumn("Status"),
            "last_seen": st.column_config.DatetimeColumn("Último Eco", format="DD/MM/YYYY - HH:mm:ss"),
        },
        height=400,
        hide_index=True,
        use_container_width=True
    )

    # ── Operaciones individuales ────────────────────────────────
    render_section_divider("Operaciones Individuales de Nodo")

    col_sel, col_action = st.columns([1, 1.5])

    with col_sel:
        available_ips = devices_df['ip'].dropna().unique().tolist()
        selected_ip = st.selectbox("🎯 Apuntar radar al Dispositivo:", available_ips)

    with col_action:
        with st.expander("📝 Etiquetado Semántico Manual", expanded=False):
            with st.form("edit_device_form", clear_on_submit=False):
                st.info("Etiqueta la nevera o el móvil para encontrarlo más rápido a gusto visual.")
                new_hostname = st.text_input("Alias (Ej. Portátil-Mamá):")
                new_notes = st.text_input("Comentarios:")

                submit = st.form_submit_button("Guardar en base de datos")

                if submit and selected_ip:
                    from src.dashboard.utils.data_loader import get_db
                    get_db().update_device_label(selected_ip, new_hostname, new_notes)
                    st.success("Dato persistido.")
                    st.rerun()

        with st.expander("🕵️‍♂️ Nmap Action Scanner (Force Ping)", expanded=False):
            st.warning("**Aviso de Invasión Acústica:** Esto puede disparar antivirus remotos si atacas a la familia u oficinas colaterales.")
            if st.button("Lanzar barrido TCP Full (Bloqueante)", type="primary"):
                if selected_ip:
                    with st.spinner(f"Escaneando espectro radiofónico y TCP en {selected_ip}..."):
                        from src.crawler.nmap_scanner import NmapScanner
                        from src.dashboard.utils.data_loader import get_db

                        scanner = NmapScanner(db=get_db())
                        result = scanner.scan_device(selected_ip)

                        if result and (result.get("open_ports") or result.get("os_guess")):
                            get_db().save_device(result)
                            st.success(f"OS Encontrado: {result.get('os_guess', 'Desconocido')}")
                            time.sleep(2.5)
                            st.rerun()
                        else:
                            st.error("El host rebotó todos los paquetes (Stealth Mode / Firewall encendido).")

render_footer()

# ── Auto-Refresh ────────────────────────────────────────────────
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
