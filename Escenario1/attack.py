import math
import time
from hashlib import sha256
from Crypto.Cipher import Salsa20
import json
import os

# Parámetros obtenidos por el atacante (mediante Wireshark o similar)
p = 13926985804350796967  # Primo p
g = 4460925131279825939   # Generador g
public_key_server = 10105297780866266891  # Llave pública del servidor
public_key_client = 7476845468886874535  # Llave pública del cliente
ciphertext = b'\xf8cf\xca\xcbY\x08\x88\t&V>\xd4\x18.\xd7\x9e\xe8\x7f\x93\xaa/\x94\xbc\x05%h' # Mensaje cifrado interceptado

# Salsa20 nonce and ciphertext splitting
nonce = ciphertext[:8]
ciphertext = ciphertext[8:]

# Definir el límite de tiempo de una hora (3600 segundos)
time_limit = 3600  # 1 hora en segundos
start_time = time.time()

# Obtener el directorio actual del script
current_directory = os.path.dirname(os.path.abspath(__file__))
baby_steps_file = os.path.join(current_directory, "baby_steps.json")

# Función para escribir los baby steps en un archivo JSON
def write_baby_step_to_file(step, value, filename):
    with open(filename, "a") as f:
        json.dump({str(step): value}, f)
        f.write("\n")  # Añadir salto de línea para cada entrada

# Función para buscar un valor en el archivo JSON (lectura durante los giant steps)
def find_baby_step_in_file(value, filename):
    with open(filename, "r") as f:
        for line in f:
            step = json.loads(line)
            if str(value) in step:
                return step[str(value)]
    return None

# Algoritmo Baby-step Giant-step para resolver el logaritmo discreto
def baby_step_giant_step_with_timeout(p, g, h, time_limit):
    m = math.isqrt(p) + 1  # Calcular m tal que m^2 >= p

    # Si el archivo ya existe, eliminarlo para evitar conflictos previos
    if os.path.exists(baby_steps_file):
        os.remove(baby_steps_file)

    print("Creando y guardando los baby steps en el archivo...")

    # Crear y escribir los baby steps en un archivo
    for j in range(m):
        value = pow(g, j, p)
        write_baby_step_to_file(value, j, baby_steps_file)

    print("Baby steps creados y guardados en el archivo.")

    # Calcular g^(-m) mod p
    g_inv_m = pow(g, -m, p)
    print("Iniciando giant-steps...")

    # Giant steps
    for i in range(m):
        elapsed_time = time.time() - start_time
        if elapsed_time > time_limit:
            print(f"Tiempo limite alcanzado ({elapsed_time:.2f} segundos).")
            return None

        # Calcular y
        y = (h * pow(g_inv_m, i, p)) % p
        # Buscar el valor en el archivo en lugar de en memoria
        baby_step = find_baby_step_in_file(y, baby_steps_file)
        if baby_step is not None:
            return i * m + int(baby_step)

    return None  # No se encontró la llave privada

# Intentar resolver el problema del logaritmo discreto para obtener la llave privada del servidor
private_key_server = baby_step_giant_step_with_timeout(p, g, public_key_server, time_limit)

total_time = time.time() - start_time  # Tiempo total transcurrido

if private_key_server is not None:
    print(f"El atacante encontró la llave privada del servidor: {private_key_server}")
    
    # Calcular el secreto compartido
    shared_secret = pow(public_key_client, private_key_server, p)
    print(f"El secreto compartido es: {shared_secret}")

    # Derivar la llave simétrica utilizando SHA-256
    shared_key = sha256(str(shared_secret).encode()).digest()
    print(f"La llave simétrica derivada es: {shared_key}")

    # Descifrar el mensaje usando Salsa20
    cipher = Salsa20.new(key=shared_key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print(f"Mensaje descifrado: {plaintext.decode()}")
else:
    print("No fue posible encontrar la llave privada.")

print(f"Tiempo total transcurrido: {total_time:.2f} segundos")
