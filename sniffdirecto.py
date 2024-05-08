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
recuento_plc = {plc: {"R": 0, "ADUQuery": 0} for plc in mapeo_ips.values()}

# Definir el filtro de captura para todos los paquetes TCP
def filtro_tcp(packet):
    return TCP in packet

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
            recuento_plc[plc_src][tipo_mensaje] += 1
            recuento_plc[plc_dest][tipo_mensaje] += 1

    # Construir el mensaje completo con toda la información acumulada
    mensaje = "Recuento de queries (Q) y responses (R) para todos los PLCs:\n"
    for plc_src, stats in recuento_plc.items():
        mensaje += f"Q {plc_src}: {stats['Q']}, R {plc_src}: {stats['R']}\n"

    # Enviar el mensaje completo al servidor de registro como un solo mensaje
    logger.debug(mensaje)

# Set logs
logger = logging.getLogger("gelf")
logger.setLevel(logging.DEBUG)

handler = GELFUDPHandler(host="192.168.222.66", port=5514)
logger.addHandler(handler)

# Iniciar la captura
sniff(prn=manejar_paquete, lfilter=filtro_tcp, iface="Ethernet", store=False)


# Construir el mensaje completo con toda la información acumulada
mensaje = ""
for plc_src, stats in recuento_plc.items():
    mensaje += f"{plc_src}: Queries={stats['Q']}, Responses={stats['R']}\n"

# Enviar el mensaje completo al servidor de registro como un solo mensaje
logger.debug(mensaje)
