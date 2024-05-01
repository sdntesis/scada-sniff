import pcapy

pcap_file = "captura_modbus.pcap"

# Abre el archivo pcap para lectura
pcap = pcapy.open_offline(pcap_file)

# Lee cada paquete del archivo pcap
while True:
    # Lee el siguiente paquete
    header, packet = pcap.next()

    # Verifica si hemos llegado al final del archivo
    if not packet:
        break

    # Haz lo que necesites con el paquete, por ejemplo, imprimir su contenido
    print(packet)

