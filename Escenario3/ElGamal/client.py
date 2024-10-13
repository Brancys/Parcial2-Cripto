from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
import socket

# Crear socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65433))
print("Conexión establecida con el servidor ElGamal.")

# Recibir la llave pública del servidor
public_key = ElGamal.import_key(client_socket.recv(1024))

# Comunicación cíclica
while True:
    # Enviar un mensaje al servidor
    message = input("Escribe tu mensaje (o 'exit' para salir): ").encode()
    encrypted_message = public_key.encrypt(message, get_random_bytes(16))
    client_socket.sendall(encrypted_message)

    if message.lower() == b"exit":
        print("Cliente ha finalizado la comunicación.")
        break

    # Recibir respuesta del servidor
    encrypted_response = client_socket.recv(1024)
    decrypted_response = public_key.decrypt(encrypted_response)
    print(f"Servidor: {decrypted_response.decode()}")

    if decrypted_response.decode().lower() == "exit":
        print("Servidor ha finalizado la comunicación.")
        break

client_socket.close()
print("Conexión cerrada.")
