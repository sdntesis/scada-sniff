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

# Contadores para ADUResponses, ADURequests y ADUQueries
num_adu_responses = 0
num_adu_queries = 0

# Definir el filtro de captura para todos los paquetes TCP
def filtro_tcp(packet):
    return TCP in packet

# Función para manejar cada paquete capturado
def manejar_paquete(packet):
    global num_adu_responses, num_adu_queries
    
    tipo_mensaje = None  # Inicializar la variable tipo_mensaje
    
    if TCP in packet:
        ipsrc = packet[IP].src
        ipdest = packet[IP].dst
        
        if packet[TCP].dport == 502:
            num_adu_queries += 1
            tipo_mensaje = "ADUQuery"
            print("Paquete Modbus capturado - ADUQuery:")
            print(packet.summary())
        elif packet[TCP].sport == 502:
            num_adu_responses += 1
            tipo_mensaje = "ADUResponse"
            print("Paquete Modbus capturado - ADUResponse:")
            print(packet.summary())
    
    if tipo_mensaje is not None:  # Verificar si tipo_mensaje ha sido asignado antes de utilizarlo
        nombre_ipsrc = mapeo_ips.get(ipsrc, "Desconocido")
        nombre_ipdest = mapeo_ips.get(ipdest, "Desconocido")
        logger.debug("Mensaje Modbus: Tipo=%s, IP_SRC=%s(%s), IP_DST=%s(%s)", tipo_mensaje, ipsrc, nombre_ipsrc, ipdest, nombre_ipdest)


        
        nombre_ipsrc = mapeo_ips.get(ipsrc, "Desconocido")
        nombre_ipdest = mapeo_ips.get(ipdest, "Desconocido")
        
        logger.debug("Mensaje Modbus: Tipo=%s, IP_SRC=%s(%s), IP_DST=%s(%s)", tipo_mensaje, ipsrc, nombre_ipsrc, ipdest, nombre_ipdest)
        logger.debug("Puerto origen: %s, Puerto destino: %s", packet[TCP].sport, packet[TCP].dport)
        
        # Enviar el número de queries y responses en los registros de registro
        logger.debug("Número de queries: %d, Número de responses: %d", num_adu_queries, num_adu_responses)
        
        # Imprimir los mensajes enviados
        print("Mensaje enviado:")
        print(f"Tipo: {tipo_mensaje}")
        print(f"IP_SRC: {ipsrc} ({nombre_ipsrc}), IP_DST: {ipdest} ({nombre_ipdest})")
        print(f"Puerto origen: {packet[TCP].sport}, Puerto destino: {packet[TCP].dport}")
        print(f"Número de queries: {num_adu_queries}, Número de responses: {num_adu_responses}")

# Set logs
logger = logging.getLogger("gelf")
logger.setLevel(logging.DEBUG)

handler = GELFUDPHandler(host="127.0.0.1", port=5514)
logger.addHandler(handler)

# Iniciar la captura
sniff(prn=manejar_paquete, lfilter=filtro_tcp, iface="ens36", store=False)
