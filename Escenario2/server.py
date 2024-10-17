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

# Generar claves elípticas (P256)
server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
server_public_key = server_private_key.public_key()

# Serializar la clave pública
server_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# Crear el socket del servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('192.168.1.15', 65432))  # Dirección IP de PC A (servidor)
server_socket.listen()

print("Servidor en espera de conexiones...")

conn, addr = server_socket.accept()
print(f"Conexión establecida con {addr}")

# Enviar la clave pública al cliente
conn.sendall(server_public_bytes)

# Recibir la clave pública del cliente
client_public_bytes = conn.recv(1024)
client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public_bytes)

# Derivar la llave simétrica
shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
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
    ciphertext = conn.recv(1024)
    if not ciphertext:
        print("Conexión cerrada.")
        break

    message = aes_decrypt(derived_key, ciphertext)
    print(f"Mensaje recibido: {message.decode()}")

    # Enviar una respuesta cifrada
    response = b"Respuesta del servidor."
    ciphertext_response = aes_encrypt(derived_key, response)
    conn.sendall(ciphertext_response)

conn.close()