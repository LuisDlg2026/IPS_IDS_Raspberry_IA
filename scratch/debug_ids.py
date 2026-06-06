import os
import sys
import time
from pathlib import Path

# Agregar la raíz del proyecto al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.storage import Database
from src.ml.inference import InferenceEngine
from scapy.all import sniff, IP

def main():
    print("==================================================")
    print("        SCRIPT DE DEPURACIÓN DEL IDS/IPS")
    print("==================================================")
    
    # 1. Cargar DB y verificar configuraciones
    db = Database()
    whitelist_str = db.get_config("whitelist_ips", "", "str")
    whitelist = [ip.strip() for ip in whitelist_str.split(",") if ip.strip()]
    capture_interface = db.get_config("capture_interface", "eth0", "str")
    
    print(f"[+] Interfaz de captura configurada en DB: {capture_interface}")
    print(f"[+] Lista blanca en DB: {whitelist}")
    
    # Intentar ver interfaces en el sistema
    try:
        import psutil
        print(f"[+] Interfaces disponibles en el sistema: {list(psutil.net_if_addrs().keys())}")
    except Exception as e:
        print(f"[-] No se pudo listar interfaces con psutil: {e}")
        
    # 2. Cargar modelo ML para pruebas
    print("\n[+] Inicializando motor de inferencia ML...")
    try:
        engine = InferenceEngine()
        print(f"    Modelo cargado: {engine.model_name}")
    except Exception as e:
        print(f"❌ Error cargando modelo ML: {e}")
        return

    # 3. Detectar origen de tráfico
    vm_ip = "192.168.1.115"
    print(f"\n[+] Esperando paquetes desde la VM ({vm_ip}) para verificar captura física...")
    print("    Por favor, lanza el ataque o haz ping desde la VM hacia la Raspberry Pi.")
    print("    Presiona Ctrl+C para detener la captura manual.")
    
    captured_packets = []
    
    def packet_callback(pkt):
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            captured_packets.append(pkt)
            print(f"    [Pkt {len(captured_packets)}] {src} -> {dst} (Proto: {proto}, Len: {len(pkt)})")
            
            # Verificar si está en la whitelist
            if src in whitelist or dst in whitelist:
                print(f"      ⚠️ ¡Este flujo está OMITIDO por la LISTA BLANCA (Whitelist)!")
                
    try:
        sniff(
            iface=capture_interface,
            prn=packet_callback,
            filter=f"host {vm_ip}",
            timeout=30,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[+] Captura interrumpida por el usuario.")
    except Exception as e:
        print(f"❌ Error al iniciar sniff de Scapy en la interfaz '{capture_interface}': {e}")
        print("    Asegúrate de que el contenedor tiene privilegios NET_ADMIN y NET_RAW y de usar la interfaz correcta.")
        return
        
    print(f"\n[+] Captura finalizada. Total paquetes capturados de la VM: {len(captured_packets)}")
    if len(captured_packets) == 0:
        print("❌ NO SE RECIBIÓ NINGÚN PAQUETE DE LA VM.")
        print("    Causas probables:")
        print("    1. La interfaz de red de captura es incorrecta.")
        print("    2. El ataque/ping no está dirigido a la IP de la Raspberry Pi (192.168.1.113).")
        print("    3. La máquina virtual y la Raspberry no se comunican correctamente.")
    else:
        print("✅ Captura física OK. Los paquetes llegan al IDS.")
        print("[+] Analizando el último paquete capturado con el modelo ML...")
        # Simular feature extraction rápida para el último paquete
        from src.capture.features_adapter import FlowAggregator
        agg = FlowAggregator()
        for pkt in captured_packets[-10:]: # Usar los últimos 10 paquetes para simular flujo
            agg.add_packet(pkt)
        
        flows = agg.swap_and_get_features()
        if flows:
            for f in flows:
                res = engine.predict(f["features"])
                print(f"\n    Flujo: {f['src_ip']} -> {f['dst_ip']}")
                print(f"    Predicción ML: {res['prediction']} (Confianza: {res['confidence']:.2%})")
                print(f"    Es Ataque: {res['is_attack']} | Severidad: {res['severity']}")
                print(f"    Detalle probabilidades: {res['probabilities']}")
        else:
            print("[-] No se pudieron agrupar flujos del tráfico de debug.")

if __name__ == "__main__":
    main()
