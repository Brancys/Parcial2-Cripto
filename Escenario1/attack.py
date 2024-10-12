import math
from hashlib import sha256
from Crypto.Cipher import Salsa20
import time

# Parámetros obtenidos por el atacante (mediante Wireshark o similar)
p = 227  # Primo p
g = 12   # Generador g
public_key_server = 93  # Llave pública del servidor
public_key_client = 119  # Llave pública del cliente
ciphertext = b"\x00\x00\x00\x00\x00..."  # Mensaje cifrado

nonce = ciphertext[:8]
ciphertext = ciphertext[8:]

time_limit = 3600  # 1 hora en segundos
start_time = time.time()

def baby_step_giant_step_with_timeout(p, g, h, time_limit):
    m = math.isqrt(p) + 1  # Calcular m tal que m^2 >= p

    # Crear un diccionario para almacenar g^j mod p para j en [0, m-1]
    baby_steps = {}
    for j in range(m):
        baby_steps[pow(g, j, p)] = j

    # Calcular g^(-m) mod p
    g_inv_m = pow(g, -m, p)

    # giant steps
    for i in range(m):
        # Verificar si se ha excedido el tiempo límite
        elapsed_time = time.time() - start_time
        if elapsed_time > time_limit:
            print("Tiempo límite excedido.")
            return None

        # Calcular y
        y = (h * pow(g_inv_m, i, p)) % p
        if y in baby_steps:
            return i * m + baby_steps[y]

    return None  # No se encontró la llave privada

# Intentar resolver el problema del logaritmo discreto para obtener la llave privada del servidor
private_key_server = baby_step_giant_step_with_timeout(p, g, public_key_server, time_limit)

if private_key_server is not None:
    print(f"El atacante encontró la llave privada del servidor: {private_key_server}")
    
    shared_secret = pow(public_key_client, private_key_server, p)
    print(f"El secreto compartido es: {shared_secret}")

    shared_key = sha256(str(shared_secret).encode()).digest()
    print(f"La llave simétrica derivada es: {shared_key}")

    cipher = Salsa20.new(key=shared_key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print(f"Mensaje descifrado: {plaintext.decode()}")

else:
    print("El atacante no pudo encontrar la llave privada en menos de una hora.")
