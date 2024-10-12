from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import os

# Generar la clave privada del servidor usando la curva elíptica P-256
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()

# Serializar la llave pública para enviarla
server_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# Crear el socket del servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))  # Escuchar en localhost y puerto 65432
server_socket.listen()

print("Servidor en espera de conexiones...")

conn, addr = server_socket.accept()
print(f"Conexión establecida con: {addr}")

# Enviar la llave pública del servidor al cliente
conn.sendall(server_public_bytes)

# Recibir la llave pública del cliente
client_public_bytes = conn.recv(1024)
client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public_bytes)

# Generar la llave compartida usando Diffie-Hellman (ECDH)
shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)

# Derivar la llave simétrica utilizando HKDF con SHA-256
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_key)

print(f"Llave simétrica derivada: {derived_key.hex()}")

# Comunicación cifrada AES-256 en modo CBC
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)  # Generar un IV aleatorio
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext

# Comunicación cíclica
while True:
    # Recibir mensaje cifrado del cliente
    ciphertext = conn.recv(1024)
    if not ciphertext:
        break
    decrypted_message = aes_decrypt(derived_key, ciphertext)
    print(f"Cliente: {decrypted_message.decode()}")

    # Si el cliente envía "exit", cerrar la conexión
    if decrypted_message.decode().lower() == "exit":
        print("Cliente ha finalizado la comunicación.")
        break

    # Enviar respuesta
    message = input("Escribe tu mensaje (o 'exit' para salir): ").encode()
    encrypted_message = aes_encrypt(derived_key, message)
    conn.sendall(encrypted_message)

    # Si el servidor envía "exit", cerrar la conexión
    if message.lower() == b"exit":
        print("Haz ha finalizado la comunicación.")
        break

conn.close()
server_socket.close()
print("Conexión cerrada.")
