import math
import time
from hashlib import sha256
from Crypto.Cipher import Salsa20
import json
import os

# Parámetros obtenidos por el atacante (mediante Wireshark o similar)
p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903  # Primo p
g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579   # Generador g
public_key_server = 90000268331225807588726117267414432728309091969610766261038808565395753847133485531051787551411553357393121472573211780793221075832268161842680757461155422164323951945934823690961944292320271033161819221889792404317442036797952914888976524556263221294880554462782879805168054205623440796500326175918622354539  # Llave pública del servidor
public_key_client = 11316795122537256800039200604034987856548765296270050563593967156483261069986442116331266988306748399299870754016397500417975794562570154671257025950722118681793828178916016305734671568784057986567020608260767391020816292661010680050124248297434713488297407827425044966545434216935630530401247677753413183888  # Llave pública del cliente
ciphertext = b'\xc0\xa4\x85X\xec\xd3\xef\x19\xe1\x87)P0@\x9e\xe6C' # Mensaje cifrado interceptado

# Salsa20 nonce and ciphertext splitting
nonce = ciphertext[:8]
ciphertext = ciphertext[8:]

# Definir el límite de tiempo de una hora (3600 segundos)
time_limit = 3600  # 1 hora en segundos
start_time = time.time()

# Obtener el directorio actual del script
current_directory = os.path.dirname(os.path.abspath(__file__))
baby_steps_file = os.path.join(current_directory, "baby_steps1.json")

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
        elapsed_time = time.time() - start_time
        if elapsed_time > time_limit:
            print(f"Tiempo limite alcanzado ({elapsed_time:.2f} segundos).")
            return None

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
