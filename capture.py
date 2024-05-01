# from scapy.all import sniff, TCP
# from scapy.layers.inet import IP
# import scapy.contrib.modbus as mb
# import logging
# from graypy import GELFUDPHandler

# # Diccionario de mapeo de direcciones IP a nombres
# mapeo_ips = {
#     "192.168.222.9": "PLC apis1",
#     "192.168.222.11": "PLC1 apis2",
#     "192.168.222.12": "PLC2 apis2",
#     "192.168.222.13": "PLC3 apis2",
#     "192.168.222.14": "PLC4 apis2",
#     "192.168.222.15": "PLC apis3",
#     "192.168.222.55": "SCADA"
# }

# # Contadores para ADUResponses, ADURequests y ADUQueries
# num_adu_responses = 0
# num_adu_requests = 0
# num_adu_queries = 0

# # Definir el filtro de captura para el puerto 502 de Modbus
# def filtro_modbus(packet):
#     return TCP in packet and (packet[TCP].sport == 502 or packet[TCP].dport == 502)

# # Función para manejar cada paquete capturado
# def manejar_paquete(packet):
#     global num_adu_responses, num_adu_requests, num_adu_queries
    
#     if mb.ModbusADUResponse in packet:
#         num_adu_responses += 1
#         tipo_mensaje = "ADUResponse"
#     elif mb.ModbusADURequest in packet:
#         num_adu_requests += 1
#         tipo_mensaje = "ADURequest"
#     else:
#         # Verificar si es un paquete de tipo query
#         if packet.haslayer(mb.ModbusPDU):
#             pdu = packet[mb.ModbusPDU]
#             funcode = pdu.funcode
#             if 1 <= funcode <= 4:  # Consideramos como query los funcodes 1 a 4
#                 num_adu_queries += 1
#                 tipo_mensaje = "ADUQuery"
#             else:
#                 return
#         else:
#             return

#     ipsrc = packet[IP].src
#     ipdest = packet[IP].dst

#     nombre_ipsrc = mapeo_ips.get(ipsrc, "Desconocido")
#     nombre_ipdest = mapeo_ips.get(ipdest, "Desconocido")

#     logger.debug("Mensaje Modbus: Tipo=%s, IP_SRC=%s(%s), IP_DST=%s(%s)", tipo_mensaje, ipsrc, nombre_ipsrc, ipdest, nombre_ipdest)

#     logger.debug("ADUResponses: %d, ADURequests: %d, ADUQueries: %d", num_adu_responses, num_adu_requests, num_adu_queries)

# # Set logs
# logger = logging.getLogger("gelf")
# logger.setLevel(logging.DEBUG)

# handler = GELFUDPHandler(host="127.0.0.1", port=5514)
# logger.addHandler(handler)

# # Iniciar la captura
# sniff(prn=manejar_paquete, lfilter=filtro_modbus, iface="ens36", store=False)


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
num_adu_requests = 0
num_adu_queries = 0

# Definir el filtro de captura para el puerto 502 de Modbus
def filtro_modbus(packet):
    return TCP in packet and (packet[TCP].sport == 502 or packet[TCP].dport == 502)

# Función para manejar cada paquete capturado
def manejar_paquete(packet):
    global num_adu_responses, num_adu_requests, num_adu_queries
    
    if TCP in packet:
        ipsrc = packet[IP].src
        ipdest = packet[IP].dst
        
        if packet[TCP].dport == 502:
            num_adu_requests += 1
            tipo_mensaje = "ADURequest"
        elif packet[TCP].sport == 502:
            num_adu_responses += 1
            tipo_mensaje = "ADUResponse"
        else:
            return
        
        nombre_ipsrc = mapeo_ips.get(ipsrc, "Desconocido")
        nombre_ipdest = mapeo_ips.get(ipdest, "Desconocido")
        
        logger.debug("Mensaje Modbus: Tipo=%s, IP_SRC=%s(%s), IP_DST=%s(%s)", tipo_mensaje, ipsrc, nombre_ipsrc, ipdest, nombre_ipdest)
        
        # Verificar si es un paquete de tipo query
        if packet.haslayer("ModbusADURequest") and packet["ModbusADURequest"].funcode in [1, 2, 3, 4]:
            num_adu_queries += 1
            tipo_mensaje = "ADUQuery"
            logger.debug("Mensaje Modbus: Tipo=%s, IP_SRC=%s(%s), IP_DST=%s(%s)", tipo_mensaje, ipsrc, nombre_ipsrc, ipdest, nombre_ipdest)

# Set logs
logger = logging.getLogger("gelf")
logger.setLevel(logging.DEBUG)

handler = GELFUDPHandler(host="127.0.0.1", port=5514)
logger.addHandler(handler)

# Iniciar la captura
sniff(prn=manejar_paquete, lfilter=filtro_modbus, iface="ens36", store=False)

# Al final de la ejecución, puedes imprimir los contadores si lo deseas
#print("ADUResponses:", num_adu_responses)
#print("ADURequests:", num_adu_requests)
#print("ADUQueries:", num_adu_queries)


# Al final de la ejecución, puedes imprimir los contadores si lo deseas
#print("ADUResponses:", num_adu_responses)
#print("ADURequests:", num_adu_requests)
#print("ADUQueries:", num_adu_queries)
