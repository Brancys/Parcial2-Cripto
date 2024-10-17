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

# Cargar el conjunto i de parámetros desde el archivo JSON
params = load_parameters(4) # Se usa el conjunto 0 de parámetros en este caso
p = params["p"]
g = params["g"]
q = params["q"]

# Crear socket del cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Intentando conectar con el servidor...")
client_socket.connect(('localhost', 65432))  # Conectarse al servidor en localhost y puerto 65432
print("Conexión establecida con el servidor.")

# Generar las llaves del cliente (privada y pública) usando q
private_key_client, public_key_client = diffie_hellman_keypair(p, g, q)

# Recibir la llave pública del servidor
public_key_server = int(client_socket.recv(1024).decode())

# Enviar la llave pública del cliente al servidor
client_socket.sendall(str(public_key_client).encode())

# Generar la llave compartida
shared_key_client = generate_shared_key(private_key_client, public_key_server, p)
print("Llave compartida generada en el cliente.")

# Comunicación cíclica
while True:
    # Enviar un mensaje al servidor
    message = input("Escribe tu mensaje (o 'exit' para salir): ")
    ciphertext = encrypt_message(shared_key_client, message)
    client_socket.sendall(ciphertext)

    if message.lower() == "exit":
        print("Haz ha finalizado la comunicación.")
        break

    # Recibir respuesta del servidor
    ciphertext = client_socket.recv(1024)
    print("Mensaje cifrado: ", ciphertext)
    decrypted_message = decrypt_message(shared_key_client, ciphertext)
    print(f"Servidor: {decrypted_message}")

    if decrypted_message.lower() == "exit":
        print("Servidor ha finalizado la comunicación.")
        break

# Cerrar conexión
client_socket.close()
print("Conexión cerrada.")
