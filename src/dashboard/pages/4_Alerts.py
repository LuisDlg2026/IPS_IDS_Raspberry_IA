import streamlit as st
import pandas as pd
import time
from datetime import datetime, timedelta
from src.dashboard.utils.data_loader import (
    load_alerts_paged, load_alerts_summary_filtered, load_alerts_filtered
)
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_footer, COLORS, SEVERITY_COLORS, SEVERITY_BG
)
from src.config import DASHBOARD_REFRESH_RATE, ATTACK_SEVERITY

st.set_page_config(page_title="Alertas - IPS/IDS", page_icon="🚨", layout="wide")
inject_global_css()

# Toggle de Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="🚨",
    title="Centro de Operaciones de Seguridad (SOC)",
    subtitle="Registro inmutable de ataques clasificados mediante Inteligencia Artificial y vulnerabilidades de firmware.",
    gradient="linear-gradient(135deg, rgba(239, 68, 68, 0.12) 0%, rgba(15, 23, 42, 0.95) 60%, rgba(10, 14, 26, 1) 100%)",
    accent="linear-gradient(90deg, var(--accent-red), var(--accent-amber))"
)

# ── Filtros ─────────────────────────────────────────────────────
render_section_divider("Motor de Búsqueda y Filtrado")

col_time, col_sev, col_att, col_ip = st.columns(4)

with col_time:
    time_filter = st.selectbox(
        "Rango Temporal",
        [
            "Última 1 hora",
            "Últimas 3 horas",
            "Últimas 6 horas",
            "Últimas 12 horas",
            "Últimas 24 horas",
            "Últimos 3 días",
            "Últimos 7 días",
            "Últimos 30 días",
            "Todo el historial",
            "Personalizado (Rango de Fechas)"
        ],
        index=4  # Default to "Últimas 24 horas"
    )

with col_sev:
    severity_labels = ["Crítico", "Advertencia", "Informativo"]
    selected_labels = st.multiselect("Severidad", options=severity_labels, default=severity_labels)

with col_att:
    attack_types = ["Todos", "Benigno"] + [k for k in ATTACK_SEVERITY.keys() if k != "Normal"]
    selected_attack = st.selectbox("Tipo de Ataque", options=attack_types, index=0)

with col_ip:
    search_ip = st.text_input("Búsqueda por IP", placeholder="Ej: 192.168.1.30").strip()

# ── Procesar rango temporal ──
since = None
until = None

if time_filter == "Personalizado (Rango de Fechas)":
    sub_col1, sub_col2 = st.columns(2)
    with sub_col1:
        date_start = st.date_input("Fecha Inicio", value=datetime.now() - timedelta(days=1))
        time_start = st.time_input("Hora Inicio", value=datetime.min.time())
        since = datetime.combine(date_start, time_start).isoformat()
    with sub_col2:
        date_end = st.date_input("Fecha Fin", value=datetime.now())
        time_end = st.time_input("Hora Fin", value=datetime.max.time())
        until = datetime.combine(date_end, time_end).isoformat()
else:
    now = datetime.now()
    if time_filter == "Última 1 hora":
        since = (now - timedelta(hours=1)).isoformat()
    elif time_filter == "Últimas 3 horas":
        since = (now - timedelta(hours=3)).isoformat()
    elif time_filter == "Últimas 6 horas":
        since = (now - timedelta(hours=6)).isoformat()
    elif time_filter == "Últimas 12 horas":
        since = (now - timedelta(hours=12)).isoformat()
    elif time_filter == "Últimas 24 horas":
        since = (now - timedelta(hours=24)).isoformat()
    elif time_filter == "Últimos 3 días":
        since = (now - timedelta(days=3)).isoformat()
    elif time_filter == "Últimos 7 días":
        since = (now - timedelta(days=7)).isoformat()
    elif time_filter == "Últimos 30 días":
        since = (now - timedelta(days=30)).isoformat()

# ── Mapear severidades ──
selected_sevs = []
for label in selected_labels:
    if label == "Crítico":
        selected_sevs.append("critical")
    elif label == "Advertencia":
        selected_sevs.extend(["high", "medium", "low"])
    elif label == "Informativo":
        selected_sevs.append("info")

# ── Control de cambio de filtros para resetear página ──
filter_hash = f"{time_filter}_{time_filter=='Personalizado (Rango de Fechas)' and (since, until) or ''}_{','.join(selected_labels)}_{selected_attack}_{search_ip}"
if "last_filter_hash" not in st.session_state or st.session_state.last_filter_hash != filter_hash:
    st.session_state.current_page = 1
    st.session_state.last_filter_hash = filter_hash

# ── Mapear Tipo de Ataque a formato DB ──
db_attack_type = None
if selected_attack == "Benigno":
    db_attack_type = "Normal"
elif selected_attack != "Todos":
    db_attack_type = selected_attack

# Validar que al menos haya una severidad seleccionada
if not selected_labels:
    st.warning("⚠️ Selecciona al menos un nivel de severidad para ver las alertas.")
    render_footer()
    if auto_refresh:
        time.sleep(DASHBOARD_REFRESH_RATE)
        st.rerun()
    st.stop()

# ── Métricas dinámicas basadas en los filtros activos ──
summary_stats = load_alerts_summary_filtered(
    severities=selected_sevs,
    attack_type=db_attack_type,
    src_ip=search_ip,
    since=since,
    until=until
)
total_filtered = summary_stats.get("total", 0)
pct_critical = summary_stats.get("pct_critical", 0.0)
most_frequent_ip = summary_stats.get("most_frequent_ip", "N/A")

m_col1, m_col2, m_col3 = st.columns(3)
with m_col1:
    render_metric_card("📊", "Total Eventos", str(total_filtered), accent="blue")
with m_col2:
    render_metric_card("💀", "Eventos Críticos", f"{pct_critical:.1f}%", accent="red", glow=(pct_critical > 0))
with m_col3:
    render_metric_card("🔍", "IP Origen Frecuente", most_frequent_ip, accent="purple")

st.write("")

# ── Paginación y Tabla ──
page_size = 20
num_pages = (total_filtered - 1) // page_size + 1 if total_filtered > 0 else 1

if "current_page" not in st.session_state:
    st.session_state.current_page = 1

if st.session_state.current_page > num_pages:
    st.session_state.current_page = num_pages
if st.session_state.current_page < 1:
    st.session_state.current_page = 1

offset = (st.session_state.current_page - 1) * page_size

alerts_df = load_alerts_paged(
    limit=page_size,
    offset=offset,
    severities=selected_sevs,
    attack_type=db_attack_type,
    src_ip=search_ip,
    since=since,
    until=until
)

if alerts_df.empty:
    st.markdown("""
    <div style="
        text-align: center; padding: 60px 40px;
        background: rgba(6, 214, 160, 0.05);
        border: 1px solid rgba(6, 214, 160, 0.15);
        border-radius: 16px;
        margin-top: 20px;
    ">
        <div style="font-size: 3rem; margin-bottom: 12px;">✨</div>
        <div style="color: var(--accent-cyan); font-weight: 600; font-size: 1.1rem;">¡Enhorabuena!</div>
        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 6px;">No hay intrusiones detectadas bajo los filtros actuales en el perímetro de la red</div>
    </div>
    """, unsafe_allow_html=True)
else:
    # Función para extraer protocolo y puerto desde el flow_key
    def extract_proto_port(flow_key):
        proto = "UNKNOWN"
        port = "N/A"
        if not flow_key or not isinstance(flow_key, str):
            return proto, port
        
        parts = flow_key.split(":")
        if len(parts) >= 1:
            proto_part = parts[0]
            if proto_part in ["TCP", "UDP", "ICMP", "ARP"]:
                proto = proto_part
        
        if proto in ["TCP", "UDP"] and "->" in flow_key:
            try:
                dst_part = flow_key.split("->")[1]
                dst_subparts = dst_part.split(":")
                if len(dst_subparts) >= 2:
                    port = dst_subparts[1]
            except Exception:
                pass
        return proto, port

    proto_ports = alerts_df["flow_key"].apply(extract_proto_port)
    alerts_df["protocol"] = [p[0] for p in proto_ports]
    alerts_df["dst_port"] = [p[1] for p in proto_ports]

    # Mapear Normal a Benigno
    alerts_df["attack_type"] = alerts_df["attack_type"].replace({"Normal": "Benigno"})
    alerts_df["confidence_pct"] = alerts_df["confidence"] * 100.0

    # Columnas a mostrar
    display_df = alerts_df[[
        "timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "attack_type", "confidence_pct", "severity"
    ]].copy()

    # Formatear la severidad para mostrar en mayúsculas en la tabla
    display_df["severity"] = display_df["severity"].str.upper()

    def style_row(row):
        styles = [''] * len(row)
        cols = list(row.index)
        sev_idx = cols.index('severity')
        
        # Resaltar filas con severidad CRITICAL
        if row['severity'] == 'CRITICAL':
            for i in range(len(styles)):
                styles[i] = 'background-color: rgba(239, 68, 68, 0.08);'
        
        # Estilo de celda para la columna de Severidad
        sev_val = row['severity'].lower()
        sev_styles = {
            'critical': f'background-color: {SEVERITY_BG["critical"]}; color: {SEVERITY_COLORS["critical"]}; border-left: 4px solid {SEVERITY_COLORS["critical"]}; font-weight: bold;',
            'high': f'background-color: {SEVERITY_BG["high"]}; color: {SEVERITY_COLORS["high"]}; border-left: 4px solid {SEVERITY_COLORS["high"]}; font-weight: bold;',
            'medium': f'background-color: {SEVERITY_BG["medium"]}; color: {SEVERITY_COLORS["medium"]}; border-left: 4px solid {SEVERITY_COLORS["medium"]}; font-weight: bold;',
            'low': f'background-color: {SEVERITY_BG["low"]}; color: {SEVERITY_COLORS["low"]}; border-left: 4px solid {SEVERITY_COLORS["low"]}; font-weight: bold;',
            'info': f'background-color: {SEVERITY_BG["info"]}; color: {SEVERITY_COLORS["info"]}; border-left: 4px solid {SEVERITY_COLORS["info"]}; font-weight: bold;',
        }
        styles[sev_idx] = sev_styles.get(sev_val, '')
        return styles

    styled_df = display_df.style.apply(style_row, axis=1)

    st.dataframe(
        styled_df,
        column_config={
            "timestamp": st.column_config.DatetimeColumn("Marca de Tiempo", format="DD/MM/YY - HH:mm:ss"),
            "src_ip": st.column_config.TextColumn("IP Origen"),
            "dst_ip": st.column_config.TextColumn("IP Destino"),
            "dst_port": st.column_config.TextColumn("Puerto Destino"),
            "protocol": st.column_config.TextColumn("Protocolo"),
            "attack_type": st.column_config.TextColumn("Tipo de Ataque"),
            "confidence_pct": st.column_config.NumberColumn("Confianza ML (%)", format="%.2f%%"),
            "severity": st.column_config.TextColumn("Severidad"),
        },
        height=500,
        hide_index=True,
        use_container_width=True
    )

    # Controles de Paginación
    col_prev, col_page, col_next, col_info = st.columns([1, 1, 1, 4])
    with col_prev:
        if st.button("⬅️ Anterior", disabled=(st.session_state.current_page <= 1), use_container_width=True):
            st.session_state.current_page -= 1
            st.rerun()

    with col_page:
        st.markdown(f"<h5 style='text-align: center; margin-top: 5px;'>{st.session_state.current_page} / {num_pages}</h5>", unsafe_allow_html=True)

    with col_next:
        if st.button("Siguiente ➡️", disabled=(st.session_state.current_page >= num_pages), use_container_width=True):
            st.session_state.current_page += 1
            st.rerun()
            
    with col_info:
        start_idx = offset + 1
        end_idx = min(offset + page_size, total_filtered)
        st.markdown(f"<div style='padding-top: 5px; color: var(--text-muted); text-align: right;'>Mostrando {start_idx}-{end_idx} de {total_filtered} eventos</div>", unsafe_allow_html=True)

    # ── Exportación a CSV (Requisito RF-09) ──
    st.markdown("---")
    
    @st.cache_data(show_spinner=False)
    def convert_df_to_csv(sev_list, att_type, search_ip, time_since, time_until):
        full_filtered_df = load_alerts_filtered(
            severities=sev_list,
            attack_type=att_type,
            src_ip=search_ip,
            since=time_since,
            until=time_until
        )
        if full_filtered_df.empty:
            return b""
        
        p_ports = full_filtered_df["flow_key"].apply(extract_proto_port)
        full_filtered_df["protocol"] = [p[0] for p in p_ports]
        full_filtered_df["dst_port"] = [p[1] for p in p_ports]
        
        full_filtered_df["attack_type"] = full_filtered_df["attack_type"].replace({"Normal": "Benigno"})
        full_filtered_df["confidence_pct"] = full_filtered_df["confidence"] * 100.0
        
        report_df = full_filtered_df[[
            "timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "attack_type", "confidence_pct", "severity"
        ]]
        
        report_df.columns = ["Timestamp", "IP Origen", "IP Destino", "Puerto Destino", "Protocolo", "Tipo de Ataque", "Confianza (%)", "Severidad"]
        return report_df.to_csv(index=False).encode('utf-8')

    csv_data = convert_df_to_csv(selected_sevs, db_attack_type, search_ip, since, until)
    
    if len(csv_data) > 0:
        st.download_button(
            label="📥 Exportar Historial Filtrado (CSV)",
            data=csv_data,
            file_name=f"reporte_alertas_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

render_footer()

# Auto-Refresco
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
