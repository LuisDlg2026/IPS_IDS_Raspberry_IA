FROM python:3.12-slim-bookworm

# Evitar que Python escriba archivos .pyc y forzar stdout sin buffer
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Configurar la tarjeta de red que vamos a usar
ENV IDS_CAPTURE_IFACE=eth0

WORKDIR /app

# Instalar dependencias del sistema operativo (esenciales para scapy y pcap)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iputils-ping \
    iproute2 \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copiar requerimientos y cachear la instalación de librerías
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código del proyecto
COPY src/ ./src/
COPY data/models/ ./data/models/
COPY start_ids.py .

# Exponer el puerto de Streamlit por si no se usa network_mode: host
EXPOSE 8501

# Arrancar el script unificado que levanta backend y frontend
CMD ["python", "start_ids.py"]
