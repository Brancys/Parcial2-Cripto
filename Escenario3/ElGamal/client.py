from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
import json
import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65433))
print("Conexión establecida con el servidor ElGamal.")

# Recibir los valores de la clave pública
public_key_values = json.loads(client_socket.recv(1024).decode())

public_key = ElGamal.construct((
    int(public_key_values['p'], 16),
    int(public_key_values['g'], 16),
    int(public_key_values['y'], 16)
))

while True:
    message = input("Escribe tu mensaje (o 'exit' para salir): ").encode()
    encrypted_message = public_key.encrypt(message, get_random_bytes(16))
    client_socket.sendall(encrypted_message)

    if message.lower() == b"exit":
        print("Cliente ha finalizado la comunicación.")
        break

    encrypted_response = client_socket.recv(1024)
    decrypted_response = public_key.decrypt(encrypted_response)
    print(f"Servidor: {decrypted_response.decode()}")

    if decrypted_response.decode().lower() == "exit":
        print("Servidor ha finalizado la comunicación.")
        break

client_socket.close()
print("Conexión cerrada.")
