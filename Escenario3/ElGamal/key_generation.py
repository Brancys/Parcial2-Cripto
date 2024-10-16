from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
import json
import os

# Obtener la ruta del directorio actual del script
current_directory = os.path.dirname(os.path.abspath(__file__))

# Generar llaves ElGamal (1024 bits en lugar de 2048)
key = ElGamal.generate(1024, get_random_bytes)

# Crear el objeto de la llave pública
public_key = key.publickey()

# Almacenar las claves en formato JSON, asegurando la conversión a enteros estándar
private_key_data = {
    'p': int(key.p),  # Convertir a entero estándar de Python
    'g': int(key.g),
    'y': int(key.y),
    'x': int(key.x)   # 'x' es la clave privada
}

public_key_data = {
    'p': int(public_key.p),  # Convertir a entero estándar de Python
    'g': int(public_key.g),
    'y': int(public_key.y)   # 'y' es la clave pública
}

# Guardar la clave privada en un archivo JSON en la misma carpeta
private_key_path = os.path.join(current_directory, "keys/sk.json")
with open(private_key_path, "w") as f:
    json.dump(private_key_data, f)

# Guardar la clave pública en un archivo JSON en la misma carpeta
public_key_path = os.path.join(current_directory, "keys/pk.json")
with open(public_key_path, "w") as f:
    json.dump(public_key_data, f)

print(f"Llaves ElGamal generadas y guardadas en {current_directory} (1024 bits).")