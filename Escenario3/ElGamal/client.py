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

# Cargar la clave pública
with open(public_key_path, "r") as f:
    public_key_data = json.load(f)

# Imprimir los valores de la clave pública para verificar
print(f"Clave pública cargada: p={public_key_data['p']}, g={public_key_data['g']}, y={public_key_data['y']}")

# Reconstruir la clave pública de ElGamal
p = int(public_key_data['p'])
g = int(public_key_data['g'])
y = int(public_key_data['y'])

# Función para cifrar manualmente usando ElGamal
def elgamal_encrypt(message, p, g, y):
    # Convertir el mensaje a un número entero
    m = int.from_bytes(message.encode(), 'big')
    
    # Elegir un valor aleatorio k
    k = random.StrongRandom().randint(1, p-1)

    # Generar c1 y c2
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p

    return (c1, c2)

# Crear un ciclo de comunicación
while True:
    try:
        # Escribir el mensaje a enviar
        message = input("Escribe tu mensaje (o 'exit' para salir): ")

        if message.lower() == "exit":
            print("Conexión cerrada por el cliente.")
            break

        # Cifrar el mensaje con ElGamal manualmente
        try:
            c1, c2 = elgamal_encrypt(message, p, g, y)
            print(f"Mensaje cifrado: c1={c1}, c2={c2}")
        except Exception as encrypt_error:
            print(f"Error durante el cifrado: {encrypt_error}")
            continue

        # Convertir los valores cifrados a cadenas Base64 para enviarlas
        cipher_text_b64_c1 = base64.b64encode(str(c1).encode()).decode()
        cipher_text_b64_c2 = base64.b64encode(str(c2).encode()).decode()

        # Enviar los valores cifrados al servidor
        client_socket.sendall(cipher_text_b64_c1.encode())
        client_socket.sendall(cipher_text_b64_c2.encode())

        # Recibir la respuesta del servidor
        server_response = client_socket.recv(2048)

        if not server_response:
            print("No se recibió respuesta del servidor.")
            break

        # Decodificar la respuesta del servidor desde Base64
        server_response = base64.b64decode(server_response)

        # Mostrar la respuesta del servidor
        print(f"Respuesta del servidor (descifrada): {server_response.decode('utf-8', errors='ignore')}")

    except Exception as e:
        print(f"Error durante la comunicación: {e}")
        break

client_socket.close()