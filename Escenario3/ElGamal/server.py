from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
import socket

# Generar llaves ElGamal (privada y pública) usando la función generadora de números aleatorios
key = ElGamal.generate(2048, get_random_bytes)

# Serializar la llave pública
public_key = key.publickey()

# Crear socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65433))
server_socket.listen()
print("Servidor ElGamal en espera...")

conn, addr = server_socket.accept()
print(f"Conexión establecida con: {addr}")

# Enviar la llave pública al cliente
conn.sendall(public_key.export_key())

# Comunicación cíclica
while True:
    # Recibir el mensaje cifrado del cliente
    encrypted_message = conn.recv(1024)
    if not encrypted_message:
        break

    # Desencriptar el mensaje usando la llave privada
    decrypted_message = key.decrypt(encrypted_message)
    print(f"Cliente: {decrypted_message.decode()}")

    if decrypted_message.decode().lower() == "exit":
        print("Cliente ha finalizado la comunicación.")
        break

    # Enviar respuesta
    message = input("Escribe tu mensaje (o 'exit' para salir): ").encode()
    encrypted_message = public_key.encrypt(message, get_random_bytes(16))
    conn.sendall(encrypted_message)

    if message.lower() == b"exit":
        print("Servidor ha finalizado la comunicación.")
        break

conn.close()
server_socket.close()
print("Conexión cerrada.")
