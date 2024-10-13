from Crypto.PublicKey import ElGamal
import json
import os
import socket

current_directory = os.path.dirname(os.path.abspath(__file__))

# Cargar la clave privada desde el archivo JSON
private_key_path = os.path.join(current_directory, "sk.json")
with open(private_key_path, "r") as f:
    private_key_data = json.load(f)

private_key = ElGamal.construct((private_key_data['p'], private_key_data['g'], private_key_data['y'], private_key_data['x']))

# Cargar la clave pública desde el archivo JSON
public_key_path = os.path.join(current_directory, "pk.json")
with open(public_key_path, "r") as f:
    public_key_data = json.load(f)

public_key = ElGamal.construct((public_key_data['p'], public_key_data['g'], public_key_data['y']))

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65433))
server_socket.listen()
print("Servidor ElGamal en espera...")

conn, addr = server_socket.accept()
print(f"Conexión establecida con: {addr}")

conn.sendall(public_key.export_key())

while True:
    encrypted_message = conn.recv(1024)
    if not encrypted_message:
        break

    decrypted_message = private_key.decrypt(encrypted_message)
    print(f"Cliente: {decrypted_message.decode()}")

    if decrypted_message.decode().lower() == "exit":
        print("Cliente ha finalizado la comunicación.")
        break

    message = input("Escribe tu mensaje (o 'exit' para salir): ").encode()
    encrypted_message = public_key.encrypt(message, get_random_bytes(16))
    conn.sendall(encrypted_message)

    if message.lower() == b"exit":
        print("Servidor ha finalizado la comunicación.")
        break

conn.close()
server_socket.close()
print("Conexión cerrada.")
