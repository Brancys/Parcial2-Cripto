import os
import socket
from hashlib import sha256
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
import json

# Obtener la ruta del archivo JSON de manera relativa
def load_parameters(i):
    base_dir = os.path.dirname(os.path.abspath(__file__))  # Directorio actual del archivo
    filename = os.path.join(base_dir, "parameters.json")  # Ruta relativa segura
    with open(filename, "r") as file:
        data = json.load(file)
    return data["parameters"][i]  # Usamos el i conjunto de parámetros

# Función para generar llaves públicas y privadas con q
def diffie_hellman_keypair(p, g, q):
    private_key = int.from_bytes(get_random_bytes(16), 'big') % q  # Llave privada en [1, q-1]
    public_key = pow(g, private_key, p)  # g^private_key mod p
    return private_key, public_key

# En este Escenario se utilizó SHA-256 como parte del proceso de Key Derivation Function (KDF)
def generate_shared_key(private_key, public_key_received, p):
    shared_secret = pow(public_key_received, private_key, p)
    shared_key = sha256(str(shared_secret).encode()).digest()
    return shared_key

# Función para cifrar un mensaje utilizando Salsa20
def encrypt_message(shared_key, message):
    cipher = Salsa20.new(key=shared_key)
    ciphertext = cipher.nonce + cipher.encrypt(message.encode())
    return ciphertext

# Función para descifrar un mensaje utilizando Salsa20
def decrypt_message(shared_key, ciphertext):
    nonce = ciphertext[:8]  # Los primeros 8 bytes son el nonce
    ciphertext = ciphertext[8:]
    cipher = Salsa20.new(key=shared_key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

# Cargar el conjunto de parametros i desde el archivo JSON
params = load_parameters(4) # Se usa el conjunto 0 de parámetros en este caso
p = params["p"]
g = params["g"]
q = params["q"]

# Crear socket del servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 65432))  # Escuchar en localhost y puerto 65432
server_socket.listen()

print("Servidor en espera de conexiones en localhost:65432...")

# Esperar la conexión del cliente
conn, addr = server_socket.accept()
print(f"Conexión establecida con: {addr}")

# Generar las llaves del servidor (privada y pública) usando q
private_key_server, public_key_server = diffie_hellman_keypair(p, g, q)

# Enviar la llave pública del servidor al cliente
conn.sendall(str(public_key_server).encode())

# Recibir la llave pública del cliente
public_key_client = int(conn.recv(1024).decode())

# Generar la llave compartida
shared_key_server = generate_shared_key(private_key_server, public_key_client, p)
print("Llave compartida generada en el servidor.")

# Comunicación cíclica
while True:
    # Recibir mensaje cifrado del cliente
    ciphertext = conn.recv(1024)
    if not ciphertext:
        break
    decrypted_message = decrypt_message(shared_key_server, ciphertext)
    print(f"Cliente: {decrypted_message}")

    # Finaliza si el cliente envía "exit"
    if decrypted_message.lower() == "exit":
        print("Cliente ha finalizado la comunicación.")
        break

    # Enviar un mensaje de respuesta
    message = input("Escribe tu mensaje (o 'exit' para salir): ")
    ciphertext = encrypt_message(shared_key_server, message)
    conn.sendall(ciphertext)

    if message.lower() == "exit":
        print("Haz finalizado la comunicación.")
        break

# Cerrar conexión
conn.close()
server_socket.close()
print("Conexión cerrada.")
