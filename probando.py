import socket
import threading
from time import sleep

# Dirección IP y puerto del servidor Modbus
SERVER_IP = "192.168.222.9"  # Cambia esto por la dirección IP de tu servidor Modbus
SERVER_PORT = 502

# Función para simular el envío de queries
def enviar_queries():
    # Crear un socket TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Conectar al servidor Modbus
        sock.connect((SERVER_IP, SERVER_PORT))
        
        for i in range(5):  # Enviar 5 queries
            query_data = b"Mensaje de query " + bytes(str(i+1), "utf-8")
            print(f"Enviando query {i+1}: {query_data.decode('utf-8')}")
            # Enviar la query al servidor
            sock.sendall(query_data)
            sleep(1)  # Esperar 1 segundo entre cada query

# Función para manejar las respuestas recibidas
def manejar_respuestas(conn):
    while True:
        # Recibir datos del servidor
        data = conn.recv(1024)
        if not data:
            break
        print("Respuesta recibida:", data.decode('utf-8'))

# Función principal
def main():
    # Iniciar hilo para enviar queries
    query_thread = threading.Thread(target=enviar_queries)
    query_thread.start()

    # Crear un socket TCP para recibir respuestas
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Enlace y escucha en el puerto
        server_socket.bind(("0.0.0.0", 0))  # Enlaza a cualquier dirección local y puerto disponible
        server_socket.listen()

        print("Esperando conexiones de respuesta...")
        conn, addr = server_socket.accept()
        print("Conexión de respuesta aceptada desde:", addr)

        # Iniciar un hilo para manejar las respuestas
        response_thread = threading.Thread(target=manejar_respuestas, args=(conn,))
        response_thread.start()

        # Esperar a que el hilo de las queries termine
        query_thread.join()

        # Esperar a que el hilo de las respuestas termine
        response_thread.join()

if __name__ == "__main__":
    main()
