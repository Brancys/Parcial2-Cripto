from Crypto.PublicKey import ElGamal
from Crypto.Random import random
import json
import socket

# Crear socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65433))
print("Conexión establecida con el servidor ElGamal.")

# Recibir los valores de la clave pública como JSON (hexadecimales)
public_key_values = json.loads(client_socket.recv(2048).decode())

# Convertir de hexadecimal a enteros para reconstruir la clave pública
public_key = ElGamal.construct((
    int(public_key_values['p'], 16),
    int(public_key_values['g'], 16),
    int(public_key_values['y'], 16)
))

p = public_key.p
g = public_key.g
y = public_key.y

# Comunicación cíclica
while True:
    # Escribir el mensaje a enviar
    message = input("Escribe tu mensaje (o 'exit' para salir): ").encode()

    # Convertir el mensaje a número
    m = int.from_bytes(message, 'big')

    # Generar un valor aleatorio k
    k = random.randint(1, p-2)

    # Cifrar el mensaje
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p

    # Enviar c1 y c2 al servidor
    client_socket.sendall(str(c1).encode())
    client_socket.sendall(str(c2).encode())

    if message.decode().lower() == "exit":
        print("Conexión cerrada por el cliente.")
        break

    # Recibir c1 y c2 de la respuesta
    c1_resp = client_socket.recv(1024).decode()
    c2_resp = client_socket.recv(1024).decode()

    if not c1_resp or not c2_resp:
        print("Mensaje vacío recibido, cerrando conexión.")
        break

    # Convertir c1 y c2 de la respuesta a enteros
    c1_resp = int(c1_resp)
    c2_resp = int(c2_resp)

    # Descifrar la respuesta
    s_resp = pow(c1_resp, private_key.x, p)
    s_inv_resp = mod_inverse(s_resp, p)
    r = (c2_resp * s_inv_resp) % p

    # Convertir el número descifrado de vuelta a texto
    response = r.to_bytes((r.bit_length() + 7) // 8, 'big').decode()
    print(f"Respuesta del servidor: {response}")

    if response.lower() == "exit":
        print("Conexión cerrada por el servidor.")
        break

client_socket.close()