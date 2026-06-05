"""
🎨 Sentinel UI — Sistema de Diseño Centralizado
=================================================
Módulo de estilos compartidos para el dashboard IPS/IDS.
Inyecta CSS global, fuentes, animaciones y proporciona funciones
helper para renderizar componentes visuales consistentes.
"""

import streamlit as st

# ─── Paleta de colores del sistema ────────────────────────────────
COLORS = {
    "bg_deep": "#0a0e1a",
    "bg_surface": "rgba(15, 23, 42, 0.8)",
    "bg_elevated": "rgba(30, 41, 59, 0.6)",
    "accent_cyan": "#06d6a0",
    "accent_blue": "#4cc9f0",
    "accent_purple": "#7c3aed",
    "accent_amber": "#f59e0b",
    "accent_red": "#ef4444",
    "accent_rose": "#fb7185",
    "text_primary": "#f1f5f9",
    "text_muted": "#94a3b8",
    "border_subtle": "rgba(148, 163, 184, 0.12)",
}

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#06d6a0",
    "info": "#4cc9f0",
}

SEVERITY_BG = {
    "critical": "rgba(239, 68, 68, 0.12)",
    "high": "rgba(249, 115, 22, 0.12)",
    "medium": "rgba(245, 158, 11, 0.12)",
    "low": "rgba(6, 214, 160, 0.12)",
    "info": "rgba(76, 201, 240, 0.12)",
}


def inject_global_css():
    """Inyecta el CSS global del sistema de diseño Sentinel UI."""
    st.html(f"""
    <style>
        /* ═══ Google Fonts ═══ */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

        /* ═══ Variables CSS Globales ═══ */
        :root {{
            --bg-deep: {COLORS["bg_deep"]};
            --bg-surface: {COLORS["bg_surface"]};
            --bg-elevated: {COLORS["bg_elevated"]};
            --accent-cyan: {COLORS["accent_cyan"]};
            --accent-blue: {COLORS["accent_blue"]};
            --accent-purple: {COLORS["accent_purple"]};
            --accent-amber: {COLORS["accent_amber"]};
            --accent-red: {COLORS["accent_red"]};
            --accent-rose: {COLORS["accent_rose"]};
            --text-primary: {COLORS["text_primary"]};
            --text-muted: {COLORS["text_muted"]};
            --border-subtle: {COLORS["border_subtle"]};
            --glass-bg: rgba(15, 23, 42, 0.65);
            --glass-border: rgba(148, 163, 184, 0.15);
            --glass-blur: 16px;
        }}

        /* ═══ Reset y Base ═══ */
        .stApp {{
            background-color: var(--bg-deep) !important;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        }}

        .stApp > header {{
            background-color: rgba(10, 14, 26, 0.8) !important;
            backdrop-filter: blur(12px) !important;
        }}

        /* Sidebar */
        section[data-testid="stSidebar"] {{
            background-color: rgba(10, 14, 26, 0.95) !important;
            border-right: 1px solid var(--glass-border) !important;
        }}

        section[data-testid="stSidebar"] .stMarkdown p,
        section[data-testid="stSidebar"] .stMarkdown span {{
            color: var(--text-muted) !important;
        }}

        /* Tipografía global */
        h1, h2, h3, h4, h5, h6 {{
            font-family: 'Inter', sans-serif !important;
            color: var(--text-primary) !important;
            font-weight: 700 !important;
            letter-spacing: -0.02em;
        }}

        p, label, .stMarkdown {{
            font-family: 'Inter', sans-serif !important;
        }}

        /* Aplicar Inter solo a spans de contenido, NO a spans de iconos */
        [data-testid="stMarkdownContainer"] span,
        [data-testid="stMetricLabel"] span,
        [data-testid="stMetricDelta"] span,
        .stRadio span,
        .stCheckbox span,
        .stSelectbox span {{
            font-family: 'Inter', sans-serif !important;
        }}

        code, .stCode, pre {{
            font-family: 'JetBrains Mono', monospace !important;
        }}

        /* Streamlit metric overrides */
        [data-testid="stMetricValue"] {{
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 2rem !important;
            font-weight: 700 !important;
            color: var(--text-primary) !important;
        }}

        [data-testid="stMetricLabel"] {{
            color: var(--text-muted) !important;
            font-size: 0.85rem !important;
            text-transform: uppercase !important;
            letter-spacing: 0.08em !important;
            font-weight: 600 !important;
        }}

        [data-testid="stMetricDelta"] {{
            font-family: 'JetBrains Mono', monospace !important;
        }}

        /* Streamlit native widgets styling */
        .stSelectbox label, .stTextInput label, .stSlider label, .stCheckbox label {{
            color: var(--text-muted) !important;
            font-weight: 500 !important;
        }}

        .stDataFrame {{
            border-radius: 12px !important;
            overflow: hidden !important;
        }}

        /* ═══ Animaciones ═══ */
        @keyframes sentinel-glow {{
            0%, 100% {{ opacity: 0.6; }}
            50% {{ opacity: 1; }}
        }}

        @keyframes sentinel-pulse {{
            0%, 100% {{ box-shadow: 0 0 5px var(--glow-color, var(--accent-cyan)); }}
            50% {{ box-shadow: 0 0 20px var(--glow-color, var(--accent-cyan)), 0 0 40px color-mix(in srgb, var(--glow-color, var(--accent-cyan)) 30%, transparent); }}
        }}

        @keyframes sentinel-float {{
            0%, 100% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(-4px); }}
        }}

        @keyframes sentinel-shimmer {{
            0% {{ background-position: -200% center; }}
            100% {{ background-position: 200% center; }}
        }}

        @keyframes sentinel-fade-in {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        /* ═══ Componentes Glassmorphism ═══ */
        .glass-card {{
            background: var(--glass-bg);
            backdrop-filter: blur(var(--glass-blur));
            -webkit-backdrop-filter: blur(var(--glass-blur));
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 24px;
            animation: sentinel-fade-in 0.5s ease-out;
            transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
        }}

        .glass-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            border-color: rgba(148, 163, 184, 0.25);
        }}

        /* Tarjeta de métrica */
        .sentinel-metric {{
            background: var(--glass-bg);
            backdrop-filter: blur(var(--glass-blur));
            -webkit-backdrop-filter: blur(var(--glass-blur));
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 20px 24px;
            position: relative;
            overflow: hidden;
            animation: sentinel-fade-in 0.5s ease-out;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}

        .sentinel-metric:hover {{
            transform: translateY(-3px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }}

        .sentinel-metric::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--metric-accent, var(--accent-blue));
            border-radius: 16px 16px 0 0;
        }}

        .sentinel-metric .metric-icon {{
            font-size: 2rem;
            margin-bottom: 8px;
            display: block;
            animation: sentinel-float 3s ease-in-out infinite;
        }}

        .sentinel-metric .metric-value {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1.2;
            margin: 4px 0;
        }}

        .sentinel-metric .metric-label {{
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            font-weight: 600;
        }}

        .sentinel-metric .metric-sub {{
            color: var(--text-muted);
            font-size: 0.75rem;
            margin-top: 6px;
            opacity: 0.7;
        }}

        /* Variantes de acento */
        .sentinel-metric.accent-cyan {{ --metric-accent: var(--accent-cyan); }}
        .sentinel-metric.accent-blue {{ --metric-accent: var(--accent-blue); }}
        .sentinel-metric.accent-purple {{ --metric-accent: var(--accent-purple); }}
        .sentinel-metric.accent-amber {{ --metric-accent: var(--accent-amber); }}
        .sentinel-metric.accent-red {{ --metric-accent: var(--accent-red); }}
        .sentinel-metric.accent-green {{ --metric-accent: #22c55e; }}

        /* Glow pulsante para estados activos */
        .sentinel-metric.glow-active {{
            --glow-color: var(--metric-accent, var(--accent-cyan));
            animation: sentinel-pulse 2.5s ease-in-out infinite, sentinel-fade-in 0.5s ease-out;
        }}

        /* ═══ Page Header ═══ */
        .sentinel-header {{
            background: var(--header-gradient, linear-gradient(135deg, #0f172a 0%, #1e293b 100%));
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 32px 36px;
            margin-bottom: 28px;
            position: relative;
            overflow: hidden;
        }}

        .sentinel-header::after {{
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--header-accent, linear-gradient(90deg, var(--accent-cyan), var(--accent-purple)));
        }}

        .sentinel-header .header-icon {{
            font-size: 2.5rem;
            margin-bottom: 8px;
            display: inline-block;
            animation: sentinel-float 3s ease-in-out infinite;
        }}

        .sentinel-header h1 {{
            font-size: 2rem !important;
            margin: 0 0 8px 0 !important;
            background: linear-gradient(135deg, var(--text-primary) 0%, var(--accent-blue) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .sentinel-header .header-subtitle {{
            color: var(--text-muted);
            font-size: 1.05rem;
            margin: 0;
            line-height: 1.5;
        }}

        /* ═══ Section Divider ═══ */
        .sentinel-divider {{
            display: flex;
            align-items: center;
            gap: 16px;
            margin: 28px 0 20px 0;
        }}

        .sentinel-divider .divider-line {{
            flex: 1;
            height: 1px;
            background: linear-gradient(90deg, var(--glass-border), transparent);
        }}

        .sentinel-divider .divider-line.right {{
            background: linear-gradient(90deg, transparent, var(--glass-border));
        }}

        .sentinel-divider .divider-title {{
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            font-weight: 600;
            white-space: nowrap;
        }}

        /* ═══ Status Badge ═══ */
        .sentinel-badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 100px;
            font-size: 0.85rem;
            font-weight: 600;
            font-family: 'Inter', sans-serif;
            border: 1px solid;
        }}

        .sentinel-badge .badge-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            animation: sentinel-glow 2s ease-in-out infinite;
        }}

        .sentinel-badge.badge-critical {{
            background: {SEVERITY_BG["critical"]};
            color: {SEVERITY_COLORS["critical"]};
            border-color: rgba(239, 68, 68, 0.3);
        }}
        .sentinel-badge.badge-critical .badge-dot {{ background: {SEVERITY_COLORS["critical"]}; }}

        .sentinel-badge.badge-high {{
            background: {SEVERITY_BG["high"]};
            color: {SEVERITY_COLORS["high"]};
            border-color: rgba(249, 115, 22, 0.3);
        }}
        .sentinel-badge.badge-high .badge-dot {{ background: {SEVERITY_COLORS["high"]}; }}

        .sentinel-badge.badge-medium {{
            background: {SEVERITY_BG["medium"]};
            color: {SEVERITY_COLORS["medium"]};
            border-color: rgba(245, 158, 11, 0.3);
        }}
        .sentinel-badge.badge-medium .badge-dot {{ background: {SEVERITY_COLORS["medium"]}; }}

        .sentinel-badge.badge-low {{
            background: {SEVERITY_BG["low"]};
            color: {SEVERITY_COLORS["low"]};
            border-color: rgba(6, 214, 160, 0.3);
        }}
        .sentinel-badge.badge-low .badge-dot {{ background: {SEVERITY_COLORS["low"]}; }}

        .sentinel-badge.badge-info {{
            background: {SEVERITY_BG["info"]};
            color: {SEVERITY_COLORS["info"]};
            border-color: rgba(76, 201, 240, 0.3);
        }}
        .sentinel-badge.badge-info .badge-dot {{ background: {SEVERITY_COLORS["info"]}; }}

        .sentinel-badge.badge-ok {{
            background: rgba(34, 197, 94, 0.12);
            color: #22c55e;
            border-color: rgba(34, 197, 94, 0.3);
        }}
        .sentinel-badge.badge-ok .badge-dot {{ background: #22c55e; }}

        /* ═══ Legend Item ═══ */
        .sentinel-legend {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 14px;
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            border-radius: 10px;
            margin-bottom: 8px;
            transition: all 0.2s ease;
        }}

        .sentinel-legend:hover {{
            background: var(--bg-elevated);
            border-color: var(--legend-color, var(--glass-border));
        }}

        .sentinel-legend .legend-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            flex-shrink: 0;
            box-shadow: 0 0 8px color-mix(in srgb, var(--legend-color) 40%, transparent);
        }}

        .sentinel-legend .legend-label {{
            color: var(--text-primary);
            font-size: 0.82rem;
            font-weight: 500;
        }}

        /* ═══ Nav Card (Landing) ═══ */
        .sentinel-nav-card {{
            background: var(--glass-bg);
            backdrop-filter: blur(var(--glass-blur));
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 24px;
            text-align: center;
            transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: default;
            position: relative;
            overflow: hidden;
        }}

        .sentinel-nav-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--card-accent, var(--accent-blue));
            transform: scaleX(0);
            transition: transform 0.35s ease;
            transform-origin: left;
        }}

        .sentinel-nav-card:hover {{
            transform: translateY(-6px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
            border-color: var(--card-accent, var(--accent-blue));
        }}

        .sentinel-nav-card:hover::before {{
            transform: scaleX(1);
        }}

        .sentinel-nav-card .nav-icon {{
            font-size: 2.5rem;
            display: block;
            margin-bottom: 12px;
        }}

        .sentinel-nav-card .nav-title {{
            color: var(--text-primary);
            font-weight: 700;
            font-size: 1rem;
            margin-bottom: 6px;
        }}

        .sentinel-nav-card .nav-desc {{
            color: var(--text-muted);
            font-size: 0.8rem;
            line-height: 1.4;
        }}

        /* ═══ Streamlit Button Override ═══ */
        .stButton > button {{
            background: var(--glass-bg) !important;
            border: 1px solid var(--glass-border) !important;
            color: var(--text-primary) !important;
            border-radius: 10px !important;
            font-family: 'Inter', sans-serif !important;
            font-weight: 600 !important;
            transition: all 0.3s ease !important;
            backdrop-filter: blur(8px) !important;
        }}

        .stButton > button:hover {{
            border-color: var(--accent-blue) !important;
            box-shadow: 0 0 15px rgba(76, 201, 240, 0.15) !important;
            transform: translateY(-1px) !important;
        }}

        .stButton > button[kind="primary"] {{
            background: linear-gradient(135deg, var(--accent-purple), var(--accent-blue)) !important;
            border: none !important;
        }}

        .stButton > button[kind="primary"]:hover {{
            box-shadow: 0 0 20px rgba(124, 58, 237, 0.3) !important;
        }}

        /* ═══ Expander Override ═══ */
        .streamlit-expanderHeader {{
            background: var(--glass-bg) !important;
            border: 1px solid var(--glass-border) !important;
            border-radius: 12px !important;
            color: var(--text-primary) !important;
            font-weight: 600 !important;
        }}

        /* ═══ Footer ═══ */
        .sentinel-footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.75rem;
            padding: 24px 0 8px 0;
            border-top: 1px solid var(--glass-border);
            margin-top: 40px;
            opacity: 0.6;
        }}
    </style>
    """)


# ─── Funciones Helper de Renderizado ──────────────────────────────

def render_page_header(icon: str, title: str, subtitle: str, gradient: str = None, accent: str = None):
    """Renderiza un header de página con gradiente y subtítulo."""
    gradient_css = gradient or "linear-gradient(135deg, #0f172a 0%, #1e293b 100%)"
    accent_css = accent or "linear-gradient(90deg, var(--accent-cyan), var(--accent-purple))"
    st.html(f"""
    <div class="sentinel-header" style="--header-gradient: {gradient_css}; --header-accent: {accent_css};">
        <span class="header-icon">{icon}</span>
        <h1>{title}</h1>
        <p class="header-subtitle">{subtitle}</p>
    </div>
    """)


def render_metric_card(icon: str, label: str, value: str, accent: str = "blue", subtitle: str = "", glow: bool = False):
    """Renderiza una tarjeta de métrica glassmorphism con icono y glow opcional."""
    glow_class = "glow-active" if glow else ""
    sub_html = f'<span class="metric-sub">{subtitle}</span>' if subtitle else ""
    st.html(f"""
    <div class="sentinel-metric accent-{accent} {glow_class}">
        <span class="metric-icon">{icon}</span>
        <span class="metric-label">{label}</span>
        <span class="metric-value">{value}</span>
        {sub_html}
    </div>
    """)


def render_section_divider(title: str):
    """Renderiza un separador de sección con título centrado y líneas degradadas."""
    st.html(f"""
    <div class="sentinel-divider">
        <div class="divider-line"></div>
        <span class="divider-title">{title}</span>
        <div class="divider-line right"></div>
    </div>
    """)


def render_status_badge(text: str, severity: str = "info"):
    """Renderiza un badge de estado con punto pulsante."""
    return f"""
    <div class="sentinel-badge badge-{severity}">
        <span class="badge-dot"></span>
        {text}
    </div>
    """


def render_legend_item(color: str, label: str):
    """Renderiza un ítem de leyenda para mapas y gráficos."""
    return f"""
    <div class="sentinel-legend" style="--legend-color: {color};">
        <span class="legend-dot" style="background-color: {color};"></span>
        <span class="legend-label">{label}</span>
    </div>
    """


def render_glass_container_start(extra_style: str = ""):
    """Abre un contenedor glassmorphism."""
    st.html(f'<div class="glass-card" style="{extra_style}">')


def render_glass_container_end():
    """Cierra un contenedor glassmorphism."""
    st.html('</div>')


def render_footer():
    """Renderiza el footer del sistema."""
    st.html("""
    <div class="sentinel-footer">
        🛡️ Sentinel UI • Desarrollado para TFM Ciberseguridad UCLM • Luis Ignacio de Luna Gómez
    </div>
    """)


def get_plotly_layout():
    """Devuelve la configuración base de Plotly coherente con Sentinel UI."""
    return dict(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#94a3b8", size=12),
        margin=dict(l=0, r=0, t=30, b=0),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#94a3b8"),
        ),
        xaxis=dict(
            gridcolor="rgba(148, 163, 184, 0.08)",
            zerolinecolor="rgba(148, 163, 184, 0.08)",
        ),
        yaxis=dict(
            gridcolor="rgba(148, 163, 184, 0.08)",
            zerolinecolor="rgba(148, 163, 184, 0.08)",
        ),
    )
