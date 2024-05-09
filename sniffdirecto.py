from scapy.all import sniff, TCP, IP
import logging
from graypy import GELFUDPHandler
import threading
import time

# Documentación
print("""
Universidad de Cuenca
Facultad de Ingeniería
Trabajo de Titulación para Ingeniero de Telecomunicaciones
Tesistas: Lourdes Gutiérrez, Claudia Padilla
Junio 2024

Documentación: Código de Sniffeo del servidor SCADA, protocolo Modbus.
Para identificar la actividad de los PLCs.
""")

# Diccionario de mapeo de direcciones IP a nombres
mapeo_ips = {
    "192.168.222.9": "PLC apis1",
    "192.168.222.11": "PLC1 apis2",
    "192.168.222.12": "PLC2 apis2",
    "192.168.222.13": "PLC3 apis2",
    "192.168.222.14": "PLC4 apis2",
    "192.168.222.15": "PLC apis3",
    "192.168.222.55": "SCADA"
}

# Diccionario para mantener el recuento de Rs y ADURequests para cada PLC
recuento_plc = {plc: {"R": 0, "Q": 0} for plc in mapeo_ips.values()}

# Función para manejar cada paquete capturado
def manejar_paquete(packet):
    global recuento_plc
    
    tipo_mensaje = None  # Inicializar la variable tipo_mensaje
    
    if TCP in packet:
        ipsrc = packet[IP].src
        ipdest = packet[IP].dst
        
        if packet[TCP].dport == 502:
            tipo_mensaje = "Q"
        elif packet[TCP].sport == 502:
            tipo_mensaje = "R"
        
        if tipo_mensaje:
            plc_src = mapeo_ips.get(ipsrc, "Desconocido")
            plc_dest = mapeo_ips.get(ipdest, "Desconocido")
            
            # Incrementar el recuento del tipo de mensaje para el PLC origen y destino
            if plc_src in recuento_plc:
                recuento_plc[plc_src][tipo_mensaje] += 1
            if plc_dest in recuento_plc:
                recuento_plc[plc_dest][tipo_mensaje] += 1
# Función para enviar el recuento por minuto y reiniciar el recuento
def enviar_conteo_por_minuto():
    global recuento_plc
    mensaje_por_minuto = "Recuento de queries (Q) y responses (R) para todos los PLCs por minuto:\n"
    for plc_src, stats in recuento_plc.items():
        mensaje_por_minuto += f"Q {plc_src}: {stats['Q']}, R {plc_src}: {stats['R']}\n"
    print("Enviando recuento por minuto:\n" + mensaje_por_minuto)
    logger.debug(mensaje_por_minuto)
    # Reiniciar el recuento por minuto
    reiniciar_recuento_por_minuto()

# Función para reiniciar el recuento por minuto
def reiniciar_recuento_por_minuto():
    global recuento_plc
    recuento_plc = {plc: {"R": 0, "Q": 0} for plc in mapeo_ips.values()}

# Set logs
logger = logging.getLogger("gelf")
logger.setLevel(logging.DEBUG)

handler = GELFUDPHandler(host="192.168.222.66", port=5514)
logger.addHandler(handler)

# Función para capturar paquetes durante un minuto y luego enviar el recuento por minuto
def capturar_y_enviar_por_minuto():
    start_time = time.time()
    while time.time() - start_time < 30:
        sniff(prn=manejar_paquete, lfilter=lambda x: TCP in x, iface="Ethernet", timeout=1, store=False)
    enviar_conteo_por_minuto()
    threading.Timer(30, capturar_y_enviar_por_minuto).start()

# Iniciar el proceso de captura y envío por minuto
capturar_y_enviar_por_minuto()
