import pcapy
from scapy.layers.inet import IP, TCP
import scapy.contrib.modbus as mb

# Abre el archivo pcap capturado por tcpdump
pcap_file = "captura_modbus.pcap"
pcap = pcapy.open_offline(pcap_file)

# Bucle para leer y analizar cada paquete
count = 0
for timestamp, pkt in pcap:
    count += 1
    try:
        # Decodifica el paquete utilizando Scapy
        packet = IP(pkt)
        
        # Verifica si es un paquete Modbus
        if packet.haslayer(mb.ModbusPDU):
            pdu = packet[mb.ModbusPDU]
            
            # Identifica el tipo de paquete Modbus
            if mb.ModbusADURequest in packet:
                print(f"Packet {count}: Modbus ADU Request")
            elif mb.ModbusADUResponse in packet:
                print(f"Packet {count}: Modbus ADU Response")
            else:
                # Verifica si es un paquete de tipo query
                funcode = pdu.funcode
                if 1 <= funcode <= 4:
                    print(f"Packet {count}: Modbus ADU Query")
    except Exception as e:
        print(f"Error processing packet {count}: {str(e)}")
