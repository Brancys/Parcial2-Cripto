from Crypto.PublicKey import ElGamal
import json
import socket
import base64
import os

# Crear socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65433))
server_socket.listen(1)
print("Servidor ElGamal en espera...")

# Obtener la ruta del directorio actual
current_directory = os.path.dirname(os.path.abspath(__file__))
private_key_path = os.path.join(current_directory, "keys", "sk.json")

# Cargar la clave privada
with open(private_key_path, "r") as f:
    private_key_data = json.load(f)

# Reconstruir la clave privada de ElGamal
p = int(private_key_data['p'])
g = int(private_key_data['g'])
y = int(private_key_data['y'])  # clave pública
x = int(private_key_data['x'])  # clave privada

# Función para descifrar manualmente usando ElGamal
def elgamal_decrypt(c1, c2, p, x):
    s = pow(c1, x, p)
    m = (c2 * pow(s, p-2, p)) % p  # Inverso modular
    return m

# Esperar la conexión del cliente
conn, addr = server_socket.accept()
print(f"Conexión establecida con: {addr}")

# Crear un ciclo para recibir los mensajes cifrados
while True:
    try:
        # Recibir los valores cifrados del cliente
        cipher_text_b64_c1 = conn.recv(1024).decode()
        cipher_text_b64_c2 = conn.recv(1024).decode()

        if not cipher_text_b64_c1 or not cipher_text_b64_c2:
            print("Mensaje vacío recibido, cerrando conexión.")
            break

        # Decodificar los valores de Base64
        c1 = int(base64.b64decode(cipher_text_b64_c1).decode())
        c2 = int(base64.b64decode(cipher_text_b64_c2).decode())

        # Descifrar el mensaje
        try:
            decrypted_message_int = elgamal_decrypt(c1, c2, p, x)
            print(f"Mensaje descifrado como entero: {decrypted_message_int}")

            # Convertir el entero de vuelta a bytes y luego a string
            decrypted_message = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')
            print(f"Mensaje descifrado: {decrypted_message}")
        except Exception as decrypt_error:
            print(f"Error durante el descifrado: {decrypt_error}")
            continue

        # Enviar la respuesta al cliente
        response = f"Mensaje recibido: {decrypted_message}"
        response_b64 = base64.b64encode(response.encode()).decode()
        conn.sendall(response_b64.encode())

    except Exception as e:
        print(f"Error durante la comunicación: {e}")
        break

conn.close()
server_socket.close()
