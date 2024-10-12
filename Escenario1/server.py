import socket
from hashlib import sha256
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
import json

# Cargar parámetros desde el archivo JSON
def load_parameters(filename="parameters.json"):
    with open(filename, "r") as file:
        data = json.load(file)
    return data["parameters"][0]  # Usamos el primer conjunto de parámetros

# Función para generar llaves públicas y privadas con q
def diffie_hellman_keypair(p, g, q):
    private_key = int.from_bytes(get_random_bytes(16), 'big') % q  # Llave privada en [1, q-1]
    public_key = pow(g, private_key, p)  # g^private_key mod p
    return private_key, public_key

# Función para generar la llave simétrica compartida
def generate_shared_key(private_key, public_key_received, p):
    shared_secret = pow(public_key_received, private_key, p)
    shared_key = sha256(str(shared_secret).encode()).digest()
    return shared_key

# Cargar parámetros desde el archivo JSON
params = load_parameters("parameters.json")
p = params["p"]
g = params["g"]
q = params["q"]

# Crear socket del cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))  # Conectarse al servidor en localhost y puerto 65432

# Generar las llaves del cliente (privada y pública) usando q
private_key_client, public_key_client = diffie_hellman_keypair(p, g, q)

# Recibir la llave pública del servidor
public_key_server = int(client_socket.recv(1024).decode())

# Enviar la llave pública del cliente al servidor
client_socket.sendall(str(public_key_client).encode())

# Generar la llave compartida
shared_key_client = generate_shared_key(private_key_client, public_key_server, p)
print("Llave compartida generada en el cliente.")

# Función para cifrar un mensaje utilizando Salsa20
def encrypt_message(shared_key, message):
    cipher = Salsa20.new(key=shared_key)
    ciphertext = cipher.nonce + cipher.encrypt(message.encode())
    return ciphertext

# Cifrar un mensaje
message = "Mensaje secreto desde el cliente."
ciphertext = encrypt_message(shared_key_client, message)

# Enviar el mensaje cifrado al servidor
client_socket.sendall(ciphertext)
print(f"Mensaje cifrado enviado: {ciphertext}")

# Cerrar conexión
client_socket.close()
