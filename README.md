<div align="center">
  <img src="https://www.uclm.es/images/logos/Logo_uclm_40.png" alt="Logo UCLM" width="150"/>
  <h1>Desarrollo de un IDS/IPS con IA para Monitoreo y Protección de Redes Domésticas y PyMEs en Raspberry Pi</h1>
</div>

**Alumno:** Luis Ignacio de Luna  Gómez 

**Máster:** [Máster Universitario en Ciberseguridad y Seguridad de la Información](https://mcsi.uclm.es/)

**Universidad:** Universidad de Castilla-La Mancha  

**Curso Académico:** 2025-2026  

---

🧑‍🏫 <strong>Tutor del trabajo</strong>
<p>Sergio Ruiz Villafranca</p>
<p></p>
<p>Contacto:</></p>

Este repositorio contiene el código fuente (`src`) y la documentación (`docs`) para el Trabajo de Fin de Máster (TFM) centrado en la creación de un Sistema de Detección y Prevención de Intrusos (IDS/IPS) ligero y eficiente, potenciado por Inteligencia Artificial y diseñado para asegurar **entornos domésticos y PyMEs (Pequeñas y Medianas Empresas)**.

## 📋 Descripción del Proyecto

El objetivo principal es desarrollar una solución de ciberseguridad accesible que permita monitorear el tráfico de una red local (hogar o pequeña empresa), detectar anomalías y posibles ataques mediante modelos de Machine Learning/Deep Learning, y tomar medidas preventivas (bloqueo de tráfico) en tiempo real.

### Objetivos Específicos
- Interfaz intuitiva diseñada para usuarios sin conocimientos técnicos avanzados ("Plug & Play").
- Captura y análisis de tráfico de red en tiempo real.
- Implementación de modelos de IA para la clasificación de tráfico (benigno vs. malicioso).
- Evaluación de seguridad de dispositivos IoT (inventario y estado de firmware).
- Despliegue optimizado en hardware de recursos limitados (Raspberry Pi).
- Panel de control integral para visualización, gestión de dispositivos y respuesta ante incidentes.

## 🚀 Herramientas Utilizadas

Este proyecto integra diversas tecnologías para lograr un ecosistema de seguridad completo en el borde (Edge Computing):

| Categoría | Herramientas / Tecnologías | Descripción |
|-----------|----------------------------|-------------|
| **Hardware** | Raspberry Pi 4/5 | Plataforma de despliegue principal. |
| **Lenguaje** | Python 3.11+ | Lenguaje base para todo el desarrollo. |
| **IA / ML** | scikit-learn, XGBoost, LightGBM, CatBoost | Modelos de ML para detección de anomalías. |
| **Redes** | Scapy, PyShark | Captura y análisis de paquetes en tiempo real. |
| **Dashboard** | Streamlit, Plotly | Interfaz web interactiva para visualización y control. |
| **Base de Datos** | SQLite, SQLAlchemy | Almacenamiento de logs y métricas temporales. |
| **Control** | iptables, netfilter | Gestión de reglas de firewall para bloqueo (IPS). |
| **Data Science** | Pandas, NumPy, SciPy, Jupyter | Análisis exploratorio y prototipado. |

## ⚙️ Características (Planned)

- **Monitoreo en tiempo real:** Análisis continuo de paquetes de red.
- **Motor de IA:** Detección de patrones de ataque conocidos y anomalías de día cero corriendo localmente.
- **Escáner y crawler IoT:** Identificación de dispositivos, chequeo de firmware y búsqueda automatizada de actualizaciones.
- **Respuesta activa (IPS):** Bloqueo automático de ataques y gestión manual de dispositivos desde el dashboard.
- **Monitoreo de rendimiento:** Muestreo de velocidad de red y métricas de rendimiento.
- **Dashboard de control:** Visualización de topología de red (mapa), estado de dispositivos y controles de bloqueo.
- **Bajo consumo:** Diseñado para operar 24/7 en una Raspberry Pi.

El repositorio se organiza separando claramente el código fuente de la documentación, facilitando la navegación y la evaluación.

```text
IPS_IDS_Raspberry_IA/
├── archivos/           # 📝 Documentación adicional y planificación
├── data/               # 📊 Datasets y modelos de ML entrenados
├── docs/               # 📄 Memorias, diagramas y recursos LaTeX/Office
├── logs/               # 📁 Registros de ejecución y capturas
├── notebooks/          # 📓 Jupyter Notebooks para exploración (EDA)
├── scripts/            # 📜 Scripts auxiliares
├── src/                # 💻 CÓDIGO FUENTE PRINCIPAL
│   ├── capture/        # Captura de paquetes y DPI
│   ├── crawler/        # Escáner de red, Nmap, y hostnames
│   ├── dashboard/      # Interfaz web en Streamlit
│   ├── detection/      # Lógica de detección de intrusos
│   ├── mitigation/     # IPS / Mitigación de alertas
│   ├── ml/             # Inferencia de Inteligencia Artificial
│   └── utils/          # Utilidades compartidas y DB
├── tests/              # 🧪 Pruebas unitarias y de integración
├── docker-compose.yml  # 🐳 Orquestación de contenedores
├── Dockerfile          # 🐳 Definición de la imagen del sistema
├── start_ids.py        # 🚀 Punto de entrada principal
└── README.md           # 📖 Este archivo
```
## � Timeline de Desarrollo (10 Sprints)

| Sprint | Tema | Duración | Estado |
|--------|------|----------|--------|
| **Sprint 0** | Configuración base, estructura de carpetas, setup Python | Semana 1-2 | ✅ Completado |
| **Sprint 1** | Captura y procesamiento de datos de red | Semana 3-4 | ✅ Completado |
| **Sprint 2** | Exploración y análisis de datasets (EDA) | Semana 5-6 | ✅ Completado |
| **Sprint 3** | Ingeniería de características y preprocesamiento | Semana 7-8 | ✅ Completado |
| **Sprint 4** | Implementación ML: modelo base y baseline | Semana 9-10 | ✅ Completado |
| **Sprint 5** | Optimización y tunning de modelos | Semana 11-12 | ✅ Completado |
| **Sprint 6** | Backend API REST y almacenamiento | Semana 13-14 | ✅ Completado |
| **Sprint 7** | Dashboard Streamlit e integración completa | Semana 15-16 | ✅ Completado |
| **Sprint 8** | Testing en Raspberry Pi y optimización hw | Semana 17-18 | ✅ Completado |
| **Sprint 9** | Documentación final, ajustes y defensa | Semana 19-20 | ⏳ Pendiente |

## 🛠️ Requisitos del Sistema

### Hardware
- Raspberry Pi 4 8GB (recomendado) o superior.
- Tarjeta MicroSD (mínimo 32GB).
- Conexión a red (Ethernet recomendado).

### Software
- **Sistema Operativo:** Raspberry Pi OS (64-bit)
- **Lenguaje:** Python 3.11 o superior
- **Gestor de paquetes:** pip 26.0+
- **Entorno virtual:** venv (Python)
- **Git:** Para control de versiones

## 📂 Estructura del Proyecto


## � Despliegue con Docker (🚀 Recomendado para Raspberry Pi)

El despliegue en la Raspberry (o servidores on-premise) se realiza mejor mediante Docker. Esto garantiza un aislamiento limpio y solventa la gestión de dependencias de sistema complejas (como **Nmap** para escaneo activo, bases de datos IEEE OUI locales, y librerías del sniffer RAW).

### 1. Clonar el repositorio
```bash
git clone https://github.com/LuisIgnaci0/IPS_IDS_Raspberry_IA.git
cd IPS_IDS_Raspberry_IA
```

### 2. Iniciar el contenedor
Ejecuta el siguiente comando para construir la imagen y lanzarla en background. Si estás conectado a la red mediante Wi-Fi en lugar del puerto Ethernet (`eth0`), deberás sobrescribir la interfaz a `wlan0`:
```bash
# Opción Ethernet (Defecto)
sudo docker-compose up --build -d

# Opción Wi-Fi
sudo IDS_CAPTURE_IFACE=wlan0 docker-compose up --build -d
```

### 3. Revisar logs (Opcional)
Para comprobar que Nmap, ARP Spoofer y el modelo ML se inician correctamente:
```bash
sudo docker-compose logs -f
```

---

## 🔧 Instalación Nativa (Desarrollo local / Debugging)

Si quieres trabajar en tu máquina personal para programar y explorar modelos.

### 1. Requisitos del sistema
En Linux/Raspberry, vas a requerir los headers de red.
```bash
sudo apt update
sudo apt install -y python3-venv python3-pip libpcap-dev nmap samba-common-bin
```

### 2. Crear entorno virtual e instalar dependencias
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# o en Windows (PowerShell):
# .\venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r src/requirements.txt
```

### 3. Iniciar desarrollo
- **Exploración:** `jupyter notebook` en la carpeta `notebooks/`
- **Dashboard Independiente:** `streamlit run src/dashboard/app.py`
- **Tests:** `pytest tests/unit/` y `pytest tests/integration/`


## 📊 Uso

Una vez que el sistema se está ejecutando (por Docker o mediante `sudo -E venv/bin/python start_ids.py` en nativo), el **Dashboard Integral** estará accesible desde el navegador web de cualquier dispositivo conectado a tu red local en:

👉 **http://<IP_DE_LA_RASPBERRY>:8501** (Por ejemplo: `http://192.168.1.100:8501`)

### Para detener el servicio:
- **Docker:** `sudo docker-compose down`
- **Nativo (venv):** Usa `Ctrl+C` en la terminal.



## 🤝 Contribución

Este es un proyecto académico individual. Sin embargo, sugerencias y comentarios son bienvenidos.

## 📄 Licencia



## ✍️ Autor

<h2>📬 <strong>Contacto</strong></h2

<ul>
<li><strong>Email: </strong><a href="mailto:correo@luisgnaciodeluna.com">correo@luisgnaciodeluna.com </a> |  <a href="mailto:ldg1008@alu.ubu.es">ldg1008@alu.ubu.es</a> | <a href="mailto:luisignacio.luna1@alu.uclm.es">luisignacio.luna1@alu.uclm.es</a></li>

 <li><strong>Web: </strong><a href="https://luisignaciodeluna.com">Luisignaciodeluna.com</a></li>
<li><strong>Linkedin: </strong><a href="https://www.linkedin.com/in/luisignaciodeluna/">Perfil</li>
 
</ul>
