from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import socket

# Generar las llaves RSA (pública y privada) del cliente
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serializar la llave pública para enviar al servidor
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Crear socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))
print("Conexión establecida con el servidor RSA OAEP.")

# Recibir la llave pública del servidor
server_public_pem = client_socket.recv(1024)

# Enviar la llave pública del cliente al servidor
client_socket.sendall(public_pem)

# Cargar la llave pública del servidor
server_public_key = serialization.load_pem_public_key(server_public_pem)

# Comunicación cíclica
while True:
    # Enviar un mensaje al servidor
    message = input("Escribe tu mensaje (o 'exit' para salir): ").encode()
    encrypted_message = server_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.sendall(encrypted_message)

    if message.lower() == b"exit":
        print("Haz finalizado la comunicación.")
        break

    # Recibir respuesta cifrada del servidor
    encrypted_response = client_socket.recv(1024)
    decrypted_response = private_key.decrypt(
        encrypted_response,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Servidor: {decrypted_response.decode()}")

    if decrypted_response.decode().lower() == "exit":
        print("Servidor ha finalizado la comunicación.")
        break

client_socket.close()
print("Conexión cerrada.")