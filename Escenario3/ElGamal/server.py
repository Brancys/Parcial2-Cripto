from Crypto.PublicKey import ElGamal
from Crypto.Random import random
from sympy import mod_inverse
import json
import os
import socket

# Obtener la ruta del directorio actual del script
current_directory = os.path.dirname(os.path.abspath(__file__))

# Cargar la clave privada desde el archivo JSON
private_key_path = os.path.join(current_directory, "keys/sk.json")
with open(private_key_path, "r") as f:
    private_key_data = json.load(f)

# Convertir de hexadecimal a enteros
private_key = ElGamal.construct((
    int(private_key_data['p'], 16),
    int(private_key_data['g'], 16),
    int(private_key_data['y'], 16),
    int(private_key_data['x'], 16)
))

# Cargar la clave pública desde el archivo JSON
public_key_path = os.path.join(current_directory, "keys/pk.json")
with open(public_key_path, "r") as f:
    public_key_data = json.load(f)

# Convertir de hexadecimal a enteros
public_key = ElGamal.construct((
    int(public_key_data['p'], 16),
    int(public_key_data['g'], 16),
    int(public_key_data['y'], 16)
))

# Crear socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65433))
server_socket.listen()
print("Servidor ElGamal en espera...")

conn, addr = server_socket.accept()
print(f"Conexión establecida con: {addr}")

# Enviar los valores de la clave pública al cliente en formato JSON
public_key_values = {
    'p': public_key_data['p'],
    'g': public_key_data['g'],
    'y': public_key_data['y']
}
conn.sendall(json.dumps(public_key_values).encode())

p = private_key.p
x = private_key.x

# Comunicación cíclica
while True:
    # Recibir c1 y c2 (valores cifrados)
    c1 = conn.recv(1024).decode()
    c2 = conn.recv(1024).decode()

    if not c1 or not c2:
        print("Mensaje vacío recibido, cerrando conexión.")
        break

    # Convertir c1 y c2 a enteros
    c1 = int(c1)
    c2 = int(c2)

    # Descifrar el mensaje
    # Calcular s = c1^x mod p
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    
    # Calcular el mensaje m = (c2 * s_inv) mod p
    m = (c2 * s_inv) % p

    # Convertir el número descifrado de vuelta a texto
    message = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
    print(f"Mensaje descifrado: {message}")

    if message.lower() == "exit":
        print("Conexión cerrada por el cliente.")
        break

    # Enviar respuesta cifrada
    response = input("Escribe tu respuesta (o 'exit' para salir): ").encode()

    # Convertir la respuesta a un número
    r = int.from_bytes(response, 'big')

    # Generar un valor aleatorio k para cifrar la respuesta
    k = random.randint(1, p-2)

    # Cifrar la respuesta
    c1_resp = pow(private_key.g, k, p)
    c2_resp = (r * pow(private_key.y, k, p)) % p

    # Enviar c1 y c2 de la respuesta al cliente
    conn.sendall(str(c1_resp).encode())
    conn.sendall(str(c2_resp).encode())

    if response.decode().lower() == "exit":
        print("Conexión cerrada por el servidor.")
        break

conn.close()
server_socket.close()