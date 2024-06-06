"""
Universidad de Cuenca
Facultad de Ingeniería
Trabajo de Titulación para Ingeniero de Telecomunicaciones
Tesistas: Lourdes Gutiérrez, Claudia Padilla
Junio 2024

Documentación: Código de Sniffeo del servidor SCADA, protocolo Modbus.
Para identificar la actividad de los PLCs. 
"""
from scapy.all import sniff, TCP, IP
import logging
from graypy import GELFUDPHandler
import threading
import time

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
recuento_plc_minuto = {plc: {"R": 0, "Q": 0} for plc in mapeo_ips.values()}

# Función para manejar cada paquete capturado
def manejar_paquete(packet):
    global recuento_plc_minuto
    
    tipo_mensaje = None
    
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
            
            if plc_src in recuento_plc_minuto:
                recuento_plc_minuto[plc_src][tipo_mensaje] += 1
            if plc_dest in recuento_plc_minuto:
                recuento_plc_minuto[plc_dest][tipo_mensaje] += 1

# Función para enviar el recuento por minuto y reiniciar el recuento
def enviar_conteo_por_minuto():
    global recuento_plc_minuto
    mensaje_por_minuto = "Recuento de queries (Q) y responses (R) para todos los PLCs por minuto:\n"
    for plc_src, stats in recuento_plc_minuto.items():
        mensaje_por_minuto += f"Q {plc_src}: {stats['Q']}, R {plc_src}: {stats['R']}\n"
    logger.debug(mensaje_por_minuto)
    reiniciar_recuento_por_minuto()

# Función para reiniciar el recuento por minuto
def reiniciar_recuento_por_minuto():
    global recuento_plc_minuto
    for plc_stats in recuento_plc_minuto.values():
        plc_stats["R"] = 0
        plc_stats["Q"] = 0

# Set logs
logger = logging.getLogger("gelf")
logger.setLevel(logging.DEBUG)

handler = GELFUDPHandler(host="192.168.222.66", port=5514)
logger.addHandler(handler)

# Iniciar el proceso de captura y envío por minuto
threading.Thread(target=capturar_y_enviar_por_minuto).start()
