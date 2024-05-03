from scapy.all import *
load_contrib("modbus")  # Asegúrate de que ModbusTCP esté disponible

def is_modbus_query(packet):
    if packet.haslayer(ModbusTCP):  # Usa ModbusTCP en lugar de Modbus
        if packet[ModbusTCP].funcCode < 128:  # Verifica que el código de función sea de una consulta
            return True
    return False

def handle_packet(packet):
    if is_modbus_query(packet):
        print("Capturado un paquete de consulta Modbus:")
        packet.show()

# Configura Scapy para escuchar en la interfaz 'ens36' y filtrar solo consultas Modbus
sniff(prn=handle_packet, lfilter=is_modbus_query, iface="ens36")
