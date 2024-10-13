from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import socket

# Generar las llaves RSA (pública y privada)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serializar la llave pública para enviar al cliente
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Crear socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen()
print("Servidor RSA OAEP en espera...")

conn, addr = server_socket.accept()
print(f"Conexión establecida con: {addr}")

# Enviar la llave pública al cliente
conn.sendall(public_pem)

# Recibir la llave pública del cliente
client_public_pem = conn.recv(1024)
client_public_key = serialization.load_pem_public_key(client_public_pem)

# Comunicación cíclica
while True:
    # Recibir el mensaje cifrado del cliente
    encrypted_message = conn.recv(1024)
    if not encrypted_message:
        break

    # Desencriptar el mensaje usando la llave privada
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"Cliente: {decrypted_message.decode()}")

    if decrypted_message.decode().lower() == "exit":
        print("Cliente ha finalizado la comunicación.")
        break

    # Enviar respuesta cifrada con la llave pública del cliente
    message = input("Escribe tu mensaje (o 'exit' para salir): ").encode()
    encrypted_message = client_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    conn.sendall(encrypted_message)

    if message.lower() == b"exit":
        print("Servidor ha finalizado la comunicación.")
        break

conn.close()
server_socket.close()
print("Conexión cerrada.")
