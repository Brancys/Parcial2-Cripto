from Crypto.PublicKey import ElGamal
import json
import os
import socket

current_directory = os.path.dirname(os.path.abspath(__file__))

private_key_path = os.path.join(current_directory, "keys/sk.json")
with open(private_key_path, "r") as f:
    private_key_data = json.load(f)

private_key = ElGamal.construct((
    int(private_key_data['p'], 16),
    int(private_key_data['g'], 16),
    int(private_key_data['y'], 16),
    int(private_key_data['x'], 16)
))

public_key_path = os.path.join(current_directory, "keys/pk.json")
with open(public_key_path, "r") as f:
    public_key_data = json.load(f)

public_key = ElGamal.construct((
    int(public_key_data['p'], 16),
    int(public_key_data['g'], 16),
    int(public_key_data['y'], 16)
))

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65433))
server_socket.listen()
print("Servidor ElGamal en espera...")

conn, addr = server_socket.accept()
print(f"Conexión establecida con: {addr}")

public_key_values = {
    'p': public_key_data['p'],
    'g': public_key_data['g'],
    'y': public_key_data['y']
}
conn.sendall(json.dumps(public_key_values).encode())

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
