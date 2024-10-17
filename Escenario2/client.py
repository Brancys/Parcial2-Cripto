import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Funciones de cifrado y descifrado AES-256 CBC
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext

# Crear claves elípticas (P256)
client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
client_public_key = client_private_key.public_key()

# Serializar la clave pública
client_public_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# Conectar al servidor
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.1.14', 65432))  # Dirección IP de PC B (donde está el atacante)

# Recibir la clave pública del servidor
server_public_bytes = client_socket.recv(1024)
server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public_bytes)

# Enviar la clave pública del cliente
client_socket.sendall(client_public_bytes)

# Derivar la llave simétrica
shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key)

print(f"Llave simétrica establecida: {derived_key.hex()}")

# Comunicación cifrada cíclica
while True:
    message = input("Escribe tu mensaje al servidor (o 'exit' para salir): ")
    if message.lower() == 'exit':
        break

    # Cifrar el mensaje
    ciphertext = aes_encrypt(derived_key, message.encode())
    client_socket.sendall(ciphertext)

    # Recibir la respuesta cifrada
    ciphertext_response = client_socket.recv(1024)
    response = aes_decrypt(derived_key, ciphertext_response)
    print(f"Respuesta del servidor: {response.decode()}")

client_socket.close()