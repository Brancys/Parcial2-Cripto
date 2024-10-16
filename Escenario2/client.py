from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import os

# Generar la clave privada del cliente usando la curva elíptica P-256
client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()

# Serializar la llave pública para enviarla
client_public_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# Crear el socket del cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('10.20.42.68', 65432))
print("Conexión establecida con el servidor.")

# Enviar la llave pública del cliente al servidor
client_socket.sendall(client_public_bytes)

# Recibir la llave pública del servidor
server_public_bytes = client_socket.recv(1024)
server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public_bytes)

# Generar la llave compartida usando Diffie-Hellman (ECDH)
shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)

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
    # Enviar un mensaje al servidor
    message = input("Escribe tu mensaje (o 'exit' para salir): ").encode()
    encrypted_message = aes_encrypt(derived_key, message)
    client_socket.sendall(encrypted_message)

    if message.lower() == b"exit":
        print("Haz finalizado la comunicación.")
        break

    # Recibir respuesta del servidor
    ciphertext = client_socket.recv(1024)
    if not ciphertext:
        break
    decrypted_message = aes_decrypt(derived_key, ciphertext)
    print(f"Servidor: {decrypted_message.decode()}")

    # Si el servidor envía "exit", cerrar la conexión
    if decrypted_message.decode().lower() == "exit":
        print("Servidor ha finalizado la comunicación.")
        break

client_socket.close()
print("Conexión cerrada.")
