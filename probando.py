from scapy.all import *
load_contrib("modbus")

def is_modbus_query(packet):
    if packet.haslayer(Modbus):
        if packet[Modbus].func_code < 128:  # Funciones menores a 128 son consultas
            return True
    return False

def handle_packet(packet):
    if is_modbus_query(packet):
        print("Capturado un paquete de consulta Modbus:")
        packet.show()

# Configura Scapy para escuchar en la interfaz ens36 y filtrar solo consultas Modbus
sniff(prn=handle_packet, lfilter=is_modbus_query, iface="ens36")
