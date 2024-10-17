from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import os

# Funciones de cifrado y descifrado AES-256 en modo CBC
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

# Crear la llave privada del servidor
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()

# Serializar la llave pública del servidor
server_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# Configurar el socket para escuchar conexiones entrantes
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('192.168.1.15', 65432))  # IP del servidor y puerto
server_socket.listen()

print("Servidor en espera de conexiones...")

# Aceptar conexión del cliente
conn, addr = server_socket.accept()
print(f"Conexión establecida con: {addr}")

# Enviar la llave pública del servidor al cliente
conn.sendall(server_public_bytes)

# Recibir la llave pública del cliente
client_public_bytes = conn.recv(1024)
client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public_bytes)

# Establecer la llave compartida
shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)

# Derivar la llave simétrica utilizando HKDF
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_key)

print(f"Llave simétrica acordada con el cliente: {derived_key.hex()}")

# Ciclo de comunicación con el cliente
while True:
    # Recibir el mensaje cifrado del cliente
    ciphertext_from_client = conn.recv(1024)
    if not ciphertext_from_client:
        break
    
    # Descifrar el mensaje
    decrypted_message = aes_decrypt(derived_key, ciphertext_from_client)
    print(f"Mensaje del cliente: {decrypted_message.decode()}")
    
    # Responder al cliente
    response = input("Escribe tu respuesta al cliente (o 'exit' para salir): ")
    if response.lower() == 'exit':
        break
    
    # Cifrar la respuesta
    ciphertext = aes_encrypt(derived_key, response.encode())
    
    # Enviar la respuesta cifrada al cliente
    conn.sendall(ciphertext)

conn.close()
server_socket.close()