import math
from hashlib import sha256
from Crypto.Cipher import Salsa20
import time

# Parámetros obtenidos por el atacante (mediante Wireshark o similar)
p = 227  # Primo p
g = 12   # Generador g
public_key_server = 3138313930353836363635323338303333343437323135383336373233353930373338313530383634323338353032303236373032343333313834353432313733343235383739333131363336303835333439323538353031393835363535303832383631363736393138353631303234303830393939343638343939303635333437363032303339333538373136303330333837333933383631373336353133363639323436343838303234313734343130333534393138353431373332363332343835323639313339333532373532373236343234393633353232383138303938383330373730323037353333393538373733353632353539303635343330303438323731303530343434373437313430353231363036383038323631353335363532343132333632313534383837303230  # Llave pública del servidor
public_key_client = 3630323330313631303430373334363337333533353534313137383736353138313238353334373332353435303333383535353131353431353530343432323332333237303632313433353631303531313731303439323137333837393039363735313238373032393336383434323935363733303638363038343132343535323230333235343532353830323630333037303131313936353838373538313034343337393439393331323836393730323030303938383731393937393132313036343539333934373739353531383232323036333836393331363038313232383638393137383335343735343430343833343739303332343439343534363331343438343037383839333937313930393135353736383637333237313130373736303731393336363230353538393036303638  # Llave pública del cliente

# Mensaje cifrado en formato hexadecimal que se intercepta (convertido a hex)
ciphertext_hex = "308a2ab095e04b7b0f77d630e0cf..."  # Mensaje cifrado en hexadecimal

# Convertir el mensaje cifrado de hexadecimal a bytes
ciphertext = bytes.fromhex(ciphertext_hex)

# Separar el nonce y el mensaje cifrado
nonce = ciphertext[:8]
ciphertext = ciphertext[8:]

time_limit = 3600  # 1 hora en segundos
start_time = time.time()

# Función para convertir bytes a hex
def bytes_to_hex(b):
    return b.hex()

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
    
    # Convertir el mensaje descifrado a hexadecimal
    hex_plaintext = bytes_to_hex(plaintext)
    print(f"Mensaje descifrado en hexadecimal: {hex_plaintext}")

else:
    print("El atacante no pudo encontrar la llave privada en menos de una hora.")