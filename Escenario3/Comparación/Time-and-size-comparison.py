import time
import json
from Crypto.PublicKey import ElGamal, RSA
from Crypto.Random import random, get_random_bytes
from Crypto.Cipher import Salsa20, AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import os

# Nota: Este script no compara el tiempo total de cada criptosistema en sí, sino de la operación de cifrado 
# y descifrado de un mensaje de prueba. Además, se compara el tamaño del mensaje cifrado en cada caso.

# Obtener el directorio actual
current_directory = os.path.dirname(os.path.abspath(__file__))

# Crear la ruta para el archivo JSON donde se guardarán los resultados
output_file = os.path.join(current_directory, "comparison_results.json")

# Crear la ruta para las llaves de ElGamal
elgamal_keys_directory = os.path.join(current_directory, "..", "ElGamal", "keys")

# ----------------------- ElGamal (asimétrico) -----------------------
def elgamal_encrypt(message, p, g, y):
    m = int.from_bytes(message.encode(), 'big')
    k = random.StrongRandom().randint(1, p-1)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2

def elgamal_decrypt(c1, c2, p, x):
    s = pow(c1, x, p)
    m = (c2 * pow(s, p-2, p)) % p  # Inverso modular
    return m

# ----------------------- Salsa20 (simétrico) -----------------------
def salsa20_encrypt(message, key):
    cipher = Salsa20.new(key=key)
    ciphertext = cipher.nonce + cipher.encrypt(message.encode())
    return ciphertext

def salsa20_decrypt(ciphertext, key):
    nonce = ciphertext[:8]
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext[8:]).decode()

# ----------------------- AES-256 (simétrico) -----------------------
def aes_encrypt(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ciphertext

def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# ----------------------- RSA OAEP (asimétrico) -----------------------
def rsa_oaep_encrypt(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

def rsa_oaep_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext).decode()

# ----------------------- Cargar claves ElGamal -----------------------
public_key_path = os.path.join(elgamal_keys_directory, "pk.json")
private_key_path = os.path.join(elgamal_keys_directory, "sk.json")

with open(public_key_path, "r") as f:
    public_key_data = json.load(f)

with open(private_key_path, "r") as f:
    private_key_data = json.load(f)

p = int(public_key_data['p'])
g = int(public_key_data['g'])
y = int(public_key_data['y'])  # clave pública
x = int(private_key_data['x'])  # clave privada

# ----------------------- Generar claves RSA OAEP -----------------------
rsa_key = RSA.generate(2048)
public_key_rsa = rsa_key.publickey()  # Clave pública
private_key_rsa = rsa_key             # Clave privada

# Mensaje a cifrar
message = "Este es un mensaje de prueba para todos los sistemas de cifrado. Este es un mensaje de prueba para todos los sistemas de cifrado."

# Diccionario para almacenar los resultados
results = {}

# ----------------------- ElGamal (asimétrico) -----------------------
start_time = time.time()
c1, c2 = elgamal_encrypt(message, p, g, y)
end_time = time.time()
elgamal_encryption_time = end_time - start_time
elgamal_size = len(str(c1)) + len(str(c2))

start_time = time.time()
decrypted_message_int = elgamal_decrypt(c1, c2, p, x)
decrypted_message = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')
end_time = time.time()
elgamal_decryption_time = end_time - start_time

# Guardar resultados ElGamal
results['ElGamal'] = {
    "encryption_time": elgamal_encryption_time,
    "decryption_time": elgamal_decryption_time,
    "encrypted_message_size": elgamal_size
}

# ----------------------- Salsa20 (simétrico) -----------------------
key_salsa20 = get_random_bytes(32)

start_time = time.time()
ciphertext_salsa20 = salsa20_encrypt(message, key_salsa20)
end_time = time.time()
salsa20_encryption_time = end_time - start_time
salsa20_size = len(ciphertext_salsa20)

start_time = time.time()
decrypted_message_salsa20 = salsa20_decrypt(ciphertext_salsa20, key_salsa20)
end_time = time.time()
salsa20_decryption_time = end_time - start_time

# Guardar resultados Salsa20
results['Salsa20'] = {
    "encryption_time": salsa20_encryption_time,
    "decryption_time": salsa20_decryption_time,
    "encrypted_message_size": salsa20_size
}

# ----------------------- AES-256 (simétrico) -----------------------
key_aes = get_random_bytes(32)  # Clave AES-256
iv_aes = get_random_bytes(16)   # IV de 16 bytes para CBC

start_time = time.time()
ciphertext_aes = aes_encrypt(message, key_aes, iv_aes)
end_time = time.time()
aes_encryption_time = end_time - start_time
aes_size = len(ciphertext_aes)

start_time = time.time()
decrypted_message_aes = aes_decrypt(ciphertext_aes, key_aes, iv_aes)
end_time = time.time()
aes_decryption_time = end_time - start_time

# Guardar resultados AES-256
results['AES-256'] = {
    "encryption_time": aes_encryption_time,
    "decryption_time": aes_decryption_time,
    "encrypted_message_size": aes_size
}

# ----------------------- RSA OAEP (asimétrico) -----------------------
start_time = time.time()
ciphertext_rsa = rsa_oaep_encrypt(message, public_key_rsa)
end_time = time.time()
rsa_encryption_time = end_time - start_time
rsa_size = len(ciphertext_rsa)

start_time = time.time()
decrypted_message_rsa = rsa_oaep_decrypt(ciphertext_rsa, private_key_rsa)
end_time = time.time()
rsa_decryption_time = end_time - start_time

# Guardar resultados RSA OAEP
results['RSA_OAEP'] = {
    "encryption_time": rsa_encryption_time,
    "decryption_time": rsa_decryption_time,
    "encrypted_message_size": rsa_size
}

# ----------------------- Guardar en JSON -----------------------
with open(output_file, "w") as f:
    json.dump(results, f, indent=4)

print(f"Resultados guardados en {output_file}")