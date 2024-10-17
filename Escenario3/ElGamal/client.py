from Crypto.PublicKey import ElGamal
from Crypto.Random import random
import json
import socket
import base64
import os

# Crear socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65433))
print("Conexión establecida con el servidor ElGamal.")

# Obtener la ruta del directorio actual
current_directory = os.path.dirname(os.path.abspath(__file__))
public_key_path = os.path.join(current_directory, "keys", "pk.json")

# Cargar la clave pública (se asume que el server generó las claves y las compartió)
with open(public_key_path, "r") as f:
    public_key_data = json.load(f)

# Reconstruir la clave pública de ElGamal
p = int(public_key_data['p'])
g = int(public_key_data['g'])
y = int(public_key_data['y'])

# Función para cifrar manualmente usando ElGamal
def elgamal_encrypt(message, p, g, y):
    m = int.from_bytes(message.encode(), 'big')
    k = random.StrongRandom().randint(1, p-1)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)

# Crear un ciclo de comunicación secuencial
while True:
    try:
        message = input("Escribe tu mensaje al servidor (o 'exit' para salir): ")

        if message.lower() == "exit":
            print("Haz cerrado la conexión.")
            break

        # Cifrar el mensaje
        c1, c2 = elgamal_encrypt(message, p, g, y)

        # Convertir los valores cifrados a Base64 y enviar al servidor
        cipher_text_b64_c1 = base64.b64encode(str(c1).encode()).decode()
        cipher_text_b64_c2 = base64.b64encode(str(c2).encode()).decode()

        client_socket.sendall(cipher_text_b64_c1.encode())
        client_socket.sendall(cipher_text_b64_c2.encode())

        # Recibir la respuesta del servidor
        server_response = client_socket.recv(2048)
        if not server_response:
            break

        # Decodificar la respuesta
        server_response = base64.b64decode(server_response).decode('utf-8', errors='ignore')
        if server_response.lower() == "exit":
            print("Conexión cerrada por el servidor.")
            break         
        
        print(f"Servidor: {server_response}")

    except Exception as e:
        print(f"Error durante la comunicación: {e}")
        break

client_socket.close()