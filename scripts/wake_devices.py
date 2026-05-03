import os
import platform
import socket
import concurrent.futures

def ping_ip(ip):
    # Detectar el SO para usar los parámetros de ping correctos
    param_count = '-n' if platform.system().lower() == 'windows' else '-c'
    param_wait = '-w' if platform.system().lower() == 'windows' else '-W'
    val_wait = '500' if platform.system().lower() == 'windows' else '1'
    
    null_redirect = 'nul' if platform.system().lower() == 'windows' else '/dev/null'
    command = f"ping {param_count} 1 {param_wait} {val_wait} {ip} > {null_redirect} 2>&1"
    
    response = os.system(command)
    if response == 0:
        print(f"[+] Dispositivo 'despierto' o detectado en: {ip}")
        return ip
    return None

def get_local_subnet():
    # Obtener IP local de forma fiable
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "192.168.1.1" # Fallback
    finally:
        s.close()
    
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}."

if __name__ == "__main__":
    print("Iniciando Escaneo ICMP Forzoso (Ping Sweep) para despertar dispositivos IoT profundamente dormidos...")
    base_ip = get_local_subnet()
    print(f"Subred detectada: {base_ip}0/24")
    
    ips_to_check = [f"{base_ip}{i}" for i in range(1, 255)]

    # Usar multithreading para lanzar todos los pings rápido
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(ping_ip, ips_to_check)

    print("\n[✓] Escaneo de despertar completado.")
    print("Por favor, revisa el Dashboard de Devices. Al haber forzado una respuesta ICMP, la Raspberry debería haber cazado el tráfico ARP/ICMP de vuelta.")
