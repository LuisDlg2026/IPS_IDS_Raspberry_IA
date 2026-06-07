import streamlit as st
import time
import json
import pandas as pd
from datetime import datetime, timedelta
from src.dashboard.utils.data_loader import load_devices, load_alerts, get_db
from src.crawler.nmap_scanner import NmapScanner
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_status_badge, render_footer,
    COLORS, SEVERITY_COLORS, SEVERITY_BG
)
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Dispositivos - IPS/IDS", page_icon="📱", layout="wide")
inject_global_css()

# Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="📱",
    title="Directorio de Dispositivos e Inventario",
    subtitle="Auditoría activa y pasiva del hardware operando en el perímetro de tu red local.",
    gradient="linear-gradient(135deg, rgba(76, 201, 240, 0.08) 0%, rgba(15, 23, 42, 0.95) 50%, rgba(124, 58, 237, 0.1) 100%)",
    accent="linear-gradient(90deg, var(--accent-blue), var(--accent-purple))"
)

# ── Filtros ─────────────────────────────────────────────────────
online_only = st.checkbox("🟢 Mostrar únicamente dispositivos conectados", value=False)

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
    # ── Consultar alertas para enriquecer las tarjetas ──
    now = datetime.now()
    since_24h = (now - timedelta(hours=24)).isoformat()
    since_7d = (now - timedelta(days=7)).isoformat()
    since_2h = (now - timedelta(hours=2))

    alerts_24h = load_alerts(limit=5000, since=since_24h)
    alerts_7d = load_alerts(limit=20000, since=since_7d)

    # ── Función para cálculo dinámico de riesgo y justificación ──
    def calculate_device_risk(row, alerts_7d_df):
        ip = row.get("ip")
        vendor = str(row.get("vendor", "Unknown")).lower()
        risk_level = str(row.get("risk_level", "low")).lower()
        open_ports_str = row.get("open_ports", "[]")
        
        # Parsear puertos
        open_ports = []
        if open_ports_str:
            try:
                open_ports = json.loads(open_ports_str)
                if not isinstance(open_ports, list):
                    open_ports = []
            except Exception:
                open_ports = []
                
        # Factor 1: Puertos de riesgo
        risky_ports = ["23", "21", "502", "1883", "3389", "80"]
        found_risky_ports = []
        for port_desc in open_ports:
            port_num = port_desc.split("/")[0] if "/" in port_desc else port_desc
            if port_num in risky_ports:
                found_risky_ports.append(port_num)
                
        # Factor 2: Credenciales por defecto por OUI
        default_creds_vendors = ["esp32", "esp8266", "siemens", "hikvision", "tp-link", "unknown"]
        has_default_creds = any(v in vendor for v in default_creds_vendors)
        
        # Factor 3: Comportamiento IDS (7 días)
        ip_alerts = alerts_7d_df[(alerts_7d_df["src_ip"] == ip) | (alerts_7d_df["dst_ip"] == ip)]
        alerts_count = len(ip_alerts)
        critical_alerts = len(ip_alerts[ip_alerts["severity"] == "critical"])
        
        # Factor 4: Auditoría FirmwareCrawler
        has_old_firmware = risk_level in ["medium", "high", "critical"]
        
        score = 0
        justifications = []
        
        if len(open_ports) > 0:
            score += len(open_ports) * 8
            justifications.append(f"{len(open_ports)} puertos abiertos")
            if found_risky_ports:
                score += 15
                justifications.append(f"puertos expuestos de alto riesgo ({', '.join(found_risky_ports)})")
                
        if has_default_creds:
            score += 15
            justifications.append("credenciales por defecto sospechosas por OUI de fabricante")
            
        if alerts_count > 0:
            score += min(alerts_count * 5, 40)
            if critical_alerts > 0:
                score += 25
                justifications.append("comportamiento crítico anómalo (clasificado por el IDS)")
            else:
                justifications.append(f"{alerts_count} flujos sospechosos interceptados por el IDS")
                
        if has_old_firmware:
            score += 25
            justifications.append("firmware obsoleto o vulnerabilidades CVE detectadas")
            
        if score >= 55 or critical_alerts > 0:
            final_level = "critical"
            label = "Crítico"
        elif score >= 35:
            final_level = "high"
            label = "Alto"
        elif score >= 15:
            final_level = "medium"
            label = "Medio"
        else:
            final_level = "low"
            label = "Bajo"
            
        if not justifications:
            justification_text = "Dispositivo limpio, sin factores de riesgo activos."
        else:
            justification_text = f"Riesgo {label.lower()}: " + ", ".join(justifications) + "."
            
        return final_level, label, justification_text

    # ── KPIs Top ────────────────────────────────────────────────
    total_devices = len(devices_df)
    
    # Nuevos dispositivos detectados en las últimas 2 horas
    devices_df["first_seen"] = pd.to_datetime(devices_df["first_seen"])
    new_devices = len(devices_df[devices_df["first_seen"] >= pd.to_datetime(since_2h)])
    
    # Dispositivos activos con riesgo alto o crítico
    active_at_risk = 0
    for _, row in devices_df.iterrows():
        if row["is_online"] == 1:
            lvl, _, _ = calculate_device_risk(row, alerts_7d)
            if lvl in ["high", "critical"]:
                active_at_risk += 1

    col1, col2, col3 = st.columns(3)
    with col1:
        render_metric_card("📡", "Dispositivos Conocidos", str(total_devices), accent="blue")
    with col2:
        render_metric_card("🆕", "Nuevos (Últimas 2h)", str(new_devices), accent="cyan" if new_devices > 0 else "blue", glow=(new_devices > 0))
    with col3:
        render_metric_card("🔥", "Riesgo Alto/Crítico Activos", str(active_at_risk), accent="red" if active_at_risk > 0 else "green", glow=(active_at_risk > 0))

    render_section_divider("Inventario de Red")

    # Inicializar Nmap Scanner
    scanner = NmapScanner(db=get_db())

    # ── Rejilla de Tarjetas (2 columnas) ──
    cols = st.columns(2)
    
    for idx, (_, row) in enumerate(devices_df.iterrows()):
        ip = row.get("ip", "unknown")
        mac = row.get("mac", "unknown")
        vendor = row.get("vendor") or "Desconocido"
        hostname = row.get("hostname")
        is_online = row.get("is_online", 0)
        os_guess = row.get("os_guess") or "Desconocido"
        notes = row.get("notes") or ""
        
        display_name = hostname if (hostname and hostname != "None" and hostname != "") else vendor
        is_new = row["first_seen"] >= pd.to_datetime(since_2h)
        
        # Calcular riesgo dinámico
        calc_level, risk_label, risk_justification = calculate_device_risk(row, alerts_7d)
        
        # Filtrar alertas del dispositivo en 24h
        device_alerts_24h = alerts_24h[(alerts_24h["src_ip"] == ip) | (alerts_24h["dst_ip"] == ip)]
        alerts_count_24h = len(device_alerts_24h)
        
        col_card = cols[idx % 2]
        
        with col_card:
            with st.container(border=True):
                # Header de tarjeta
                header_cols = st.columns([4, 1.5])
                with header_cols[0]:
                    title_html = f"### `🖥️ {ip}`"
                    if is_new:
                        title_html += ' <span style="background-color: var(--accent-rose); color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; border: 1px solid var(--accent-red); margin-left: 8px;">🆕 NUEVO</span>'
                    st.markdown(title_html, unsafe_allow_html=True)
                with header_cols[1]:
                    # Badge de conexión
                    status_badge_text = "En Línea" if is_online == 1 else "Offline"
                    status_badge_sev = "ok" if is_online == 1 else "info"
                    
                    # Leer estado MITM para este host
                    mitm_target = get_db().get_setting("mitm_target_ip", "")
                    mitm_enabled = get_db().get_setting("mitm_enabled", "0") == "1"
                    is_intercepted = mitm_enabled and (mitm_target == ip)
                    
                    badge_html = f"{render_status_badge(status_badge_text, status_badge_sev)}"
                    if is_intercepted:
                        badge_html = f"{render_status_badge('Interceptando', 'warn')} {badge_html}"
                        
                    st.html(f"<div style='text-align: right;'>{badge_html}</div>")
                
                # Cuerpo de tarjeta
                st.markdown(f"**Nombre / OUI:** `{display_name}`")
                st.markdown(f"**Dirección MAC:** `{mac}`")
                st.markdown(f"**Sistema Operativo:** `{os_guess}`")
                
                # Tags/Notas manuales
                if notes:
                    st.markdown(f"**📝 Notas:** *{notes}*")
                
                # Puertos abiertos
                ports = []
                if row.get("open_ports"):
                    try:
                        ports = json.loads(row["open_ports"])
                    except:
                        ports = []
                if ports:
                    ports_str = ", ".join([f"`{p}`" for p in ports])
                    st.markdown(f"**🔓 Puertos Abiertos:** {ports_str}")
                else:
                    st.markdown("**🔓 Puertos Abiertos:** `Ninguno (filtrados / cerrados)`")
                
                # Nivel de riesgo con justificación textual
                risk_style = {
                    "critical": (SEVERITY_COLORS["critical"], SEVERITY_BG["critical"]),
                    "high": (SEVERITY_COLORS["high"], SEVERITY_BG["high"]),
                    "medium": (SEVERITY_COLORS["medium"], SEVERITY_BG["medium"]),
                    "low": (SEVERITY_COLORS["low"], SEVERITY_BG["low"])
                }.get(calc_level, (COLORS["text_muted"], "rgba(0,0,0,0.1)"))
                
                st.html(f"""
                <div style="margin: 12px 0; padding: 12px; background: rgba(15, 23, 42, 0.45); border: 1px solid var(--glass-border); border-radius: 10px;">
                    <span style="background-color: {risk_style[1]}; color: {risk_style[0]}; border-left: 4px solid {risk_style[0]}; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; display: inline-block;">
                        Riesgo {risk_label}
                    </span>
                    <p style="margin-top: 8px; font-size: 0.85rem; color: var(--text-muted); line-height: 1.4; margin-bottom: 0;">
                        {risk_justification}
                    </p>
                </div>
                """)
                
                # Alertas en 24 horas y auditoría firmware
                vuln_alerts = device_alerts_24h[device_alerts_24h["id"].str.startswith(("CVE-", "VULN-"), na=False)]
                
                if alerts_count_24h > 0 or not vuln_alerts.empty:
                    alert_content = ""
                    if alerts_count_24h > 0:
                        alert_content += f"⚠️ **{alerts_count_24h} alertas registradas** en las últimas 24 horas.<br>"
                    
                    if not vuln_alerts.empty:
                        alert_content += "🔍 **Vulnerabilidades activas:**<br>"
                        for _, vuln in vuln_alerts.iterrows():
                            # Limpiar la razón si está disponible
                            reason = vuln.get("details", {}).get("reason", "CVE detectado") if isinstance(vuln.get("details"), dict) else "CVE detectado"
                            alert_content += f"• `{vuln['id']}` - {reason}<br>"
                            
                    st.html(f"""
                    <div style="background: rgba(239, 68, 68, 0.06); border: 1px solid rgba(239, 68, 68, 0.15); border-radius: 8px; padding: 10px; font-size: 0.8rem; color: var(--accent-rose); line-height: 1.4; margin-bottom: 12px;">
                        {alert_content}
                    </div>
                    """)
                else:
                    st.markdown("🔒 **Seguridad:** `Sin incidentes registrados en las últimas 24h`")
                
                # Expansores de acciones individuales
                act_col1, act_col2, act_col3 = st.columns(3)
                
                with act_col1:
                    with st.expander("📝 Etiquetar", expanded=False):
                        with st.form(key=f"tag_form_{ip}", clear_on_submit=False):
                            new_host = st.text_input("Alias:", value=row.get("hostname") or "")
                            new_note = st.text_input("Comentarios:", value=row.get("notes") or "")
                            tag_submitted = st.form_submit_button("Persistir", use_container_width=True)
                            if tag_submitted:
                                get_db().update_device_label(ip, new_host, new_note)
                                st.success("¡Persistido!")
                                time.sleep(0.8)
                                st.rerun()
                                
                with act_col2:
                    if st.button("🕵️‍♂️ Re-escanear Nmap", key=f"scan_btn_{ip}", use_container_width=True):
                        scanner.scan_device_async(ip)
                        st.toast(f"🕵️‍♂️ Escaneo asíncrono Nmap iniciado para {ip}")
                        
                with act_col3:
                    # Leer estado MITM actual
                    mitm_target = get_db().get_setting("mitm_target_ip", "")
                    mitm_enabled = get_db().get_setting("mitm_enabled", "0") == "1"
                    is_intercepted = mitm_enabled and (mitm_target == ip)
                    
                    if is_intercepted:
                        if st.button("🛑 Detener Captura", key=f"mitm_btn_{ip}", type="secondary", use_container_width=True):
                            get_db().set_setting("mitm_enabled", "0")
                            st.toast("🛑 Intercepción activa desactivada.", icon="🛑")
                            time.sleep(0.5)
                            st.rerun()
                    else:
                        if st.button("🎯 Interceptar", key=f"mitm_btn_{ip}", type="primary", use_container_width=True):
                            get_db().set_setting("mitm_target_ip", ip)
                            get_db().set_setting("mitm_enabled", "1")
                            st.toast(f"🎯 Redirigiendo tráfico de {ip} al IDS...", icon="🎯")
                            time.sleep(0.5)
                            st.rerun()

st.write("")
render_footer()

# Auto-Refresco
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
