import math
import time
from hashlib import sha256
from Crypto.Cipher import Salsa20

# Parámetros obtenidos por el atacante (mediante Wireshark o similar)
p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903  # Primo p
g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579   # Generador g
public_key_server = 97886934076056264740232187787270319681106011816775524525995001258774552209046715067296773066021057523391072070988558051462379807677957593901103543600529905336590450527552190356508733909253914618986619477084897519277474375261612960593585819814005056263112517340738709486062772621811164149735182492708083511108  # Llave pública del servidor
public_key_client = 134405357736497921739626999143801705151095756195904950315911425582378630597408017855022564990002159473767512098442249029001786600589763274400287727028582422129718652092779981415284520509538189997080673665909072852854751266720170194948315743629797454034421428888884269644789521163651490491436684499512858340505  # Llave pública del cliente
ciphertext = b'\xce\xa0H\xadxxVW\xbc(\xceN'  # Mensaje cifrado interceptado

# Salsa20 nonce and ciphertext splitting
nonce = ciphertext[:8]
ciphertext = ciphertext[8:]

# Definir el límite de tiempo de una hora (3600 segundos)
time_limit = 3600  # 1 hora en segundos
start_time = time.time()

# Algoritmo Baby-step Giant-step para resolver el logaritmo discreto
def baby_step_giant_step_with_timeout(p, g, h, time_limit):
    m = math.isqrt(p) + 1  # Calcular m tal que m^2 >= p

    # Crear un diccionario para almacenar g^j mod p para j en [0, m-1]
    baby_steps = {}
    for j in range(m):
        baby_steps[pow(g, j, p)] = j

    # Calcular g^(-m) mod p
    g_inv_m = pow(g, -m, p)

    # Giant steps
    for i in range(m):
        elapsed_time = time.time() - start_time
        if elapsed_time > time_limit:
            print(f"Tiempo límite excedido después de {elapsed_time:.2f} segundos. No fue posible encontrar la llave privada.")
            return None

        # Calcular y
        y = (h * pow(g_inv_m, i, p)) % p
        if y in baby_steps:
            return i * m + baby_steps[y]

        # Mostrar tiempo transcurrido cada vez que se da un giant step
        print(f"Tiempo transcurrido: {elapsed_time:.2f} segundos")

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