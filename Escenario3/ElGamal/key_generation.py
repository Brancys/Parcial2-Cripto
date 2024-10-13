from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
import json

# Obtener la ruta del directorio actual del script
current_directory = os.path.dirname(os.path.abspath(__file__))

# Generar llaves ElGamal (1024 bits en lugar de 2048)
key = ElGamal.generate(1024, get_random_bytes)

# Crear el objeto de la llave pública
public_key = key.publickey()

# Almacenar las claves en formato JSON, pero ahora en formato hexadecimal
private_key_data = {
    'p': hex(key.p),  # Convertir a hexadecimal
    'g': hex(key.g),
    'y': hex(key.y),
    'x': hex(key.x)   # 'x' es la clave privada
}

public_key_data = {
    'p': hex(public_key.p),  # Convertir a hexadecimal
    'g': hex(public_key.g),
    'y': hex(public_key.y)   # 'y' es la clave pública
}

# Guardar la clave privada en un archivo JSON en la misma carpeta
with open("Escenario3/ElGamal/sk.json", "w") as f:
    json.dump(private_key_data, f)

# Guardar la clave pública en un archivo JSON en la misma carpeta
with open("Escenario3/ElGamal/pk.json", "w") as f:
    json.dump(public_key_data, f)

print(f"Llaves ElGamal generadas y guardadas en {current_directory} (1024 bits).")
