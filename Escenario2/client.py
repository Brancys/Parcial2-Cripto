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

# Crear la llave privada del cliente
client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()

# Serializar la llave pública del cliente
client_public_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# Conectarse al servidor (IP y puerto del servidor)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.1.14', 65432))  # Cambiar la IP si es necesario

# Enviar la llave pública del cliente al servidor
client_socket.sendall(client_public_bytes)

# Recibir la llave pública del servidor
server_public_bytes = client_socket.recv(1024)
server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public_bytes)

# Establecer la llave compartida
shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)

# Derivar la llave simétrica utilizando HKDF
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_key)

print(f"Llave simétrica acordada con el servidor: {derived_key.hex()}")

# Ciclo de comunicación con el servidor
while True:
    message = input("Escribe tu mensaje al servidor (o 'exit' para salir): ")
    if message.lower() == 'exit':
        break
    
    # Cifrar el mensaje
    ciphertext = aes_encrypt(derived_key, message.encode())
    
    # Enviar el mensaje cifrado al servidor
    client_socket.sendall(ciphertext)
    
    # Recibir la respuesta del servidor
    ciphertext_from_server = client_socket.recv(1024)
    if not ciphertext_from_server:
        break
    
    # Descifrar la respuesta
    response = aes_decrypt(derived_key, ciphertext_from_server)
    print(f"Respuesta del servidor: {response.decode()}")

client_socket.close()